(ns jepsen.hearth.db
  "Installs, seeds, starts and kills hearth on the nodes (design decisions 4
  and 5). Every node runs production mode: no --dev, TLS everywhere, fsync on.

  Setup runs on all nodes in parallel, in phases separated by barriers:

    1. install: wipe /opt/hearth, upload the binary and the node's bundle,
       run `hearth config validate`;
    2. seed (primary only): first-boot setup on a single-node store, then
       `hearth admin token` into it (scripts/seed-store.sh);
    3. copy the seeded store into every node's data directory;
    4. start every node and wait until it answers /readyz."
  (:require [clojure.java.io :as io]
            [clojure.java.shell :as shell]
            [clojure.string :as str]
            [clojure.tools.logging :refer [info warn]]
            [jepsen [control :as c]
                    [core :as jepsen]
                    [db :as db]
                    [util :as util]]
            [jepsen.control.core :as cc]
            [jepsen.control.util :as cu]
            [jepsen.hearth.http :as http]))

(def root "/opt/hearth")
(def binary (str root "/hearth"))
(def config (str root "/hearth.yaml"))
(def data-dir (str root "/data"))
(def seed-dir (str root "/seed"))
(def log-file (str root "/hearth.log"))
(def seed-log (str root "/seed.log"))
(def pid-file (str root "/hearth.pid"))
(def start-script (str root "/start.sh"))
(def https-port 8443)

(def operator-email "operator@jepsen.test")

(def system-realm "00000000-0000-0000-0000-000000000000")

(def node-ip-prefix
  "Node nX has address <prefix>.(10+X) on the Compose network."
  "10.77.0")

(defn node-url
  "The HTTPS base URL of a node."
  [node]
  (str "https://" node ":" https-port))

(defn- sh!
  "Runs a local command on the control node. Throws on a non-zero exit;
  returns stdout."
  [& args]
  (let [{:keys [exit out err]} (apply shell/sh args)]
    (when-not (zero? exit)
      (throw (ex-info (str "command failed: " (str/join " " args) "\n" err)
                      {:exit exit :out out :err err})))
    out))

(defn verify-binary!
  "Refuses a binary that `make jepsen-binary` did not produce. That target
  builds the root Dockerfile without dev-endpoints and records the binary's
  sha256 beside it. A dev build run without --dev serves no dev route, so
  the binary's origin is the only check that can tell it apart (spec: \"The
  harness is pointed at a dev binary\")."
  [binary-path]
  (let [f   (io/file binary-path)
        sum (io/file (str binary-path ".sha256"))]
    (when-not (.isFile f)
      (throw (ex-info (str "no hearth binary at " binary-path
                           "; run `make jepsen-binary`")
                      {:type ::setup-error})))
    (when-not (.isFile sum)
      (throw (ex-info (str "refusing " binary-path ": no " (.getName sum)
                           " beside it. Only a binary from `make jepsen-binary`"
                           " (built without dev-endpoints) may run")
                      {:type ::setup-error})))
    (let [expected (first (str/split (str/trim (slurp sum)) #"\s+"))
          actual   (first (str/split (sh! "sha256sum" (.getCanonicalPath f))
                                     #"\s+"))]
      (when-not (= expected actual)
        (throw (ex-info (str "refusing " binary-path ": its sha256 does not"
                             " match " (.getName sum) ". Run"
                             " `make jepsen-binary` again")
                        {:type ::setup-error :expected expected
                         :actual actual}))))
    binary-path))

(defn gen-material!
  "Generates the run's secrets, certificates and per-node bundles on the
  control node. Returns the material directory."
  [nodes]
  (let [dir (str (System/getProperty "java.io.tmpdir") "/hearth-jepsen-"
                 (random-uuid) "/material")]
    ; gen-material.sh creates `dir` itself and refuses one that exists.
    (.mkdirs (.getParentFile (io/file dir)))
    (apply sh! "scripts/gen-material.sh" (concat [dir] nodes
                                                [:env (assoc (into {} (System/getenv))
                                                             "NODE_IP_PREFIX" node-ip-prefix)]))
    (apply sh! "scripts/gen-configs.sh" dir nodes)
    (info "per-run material in" dir)
    dir))

(defn- with-master-key
  "A shell command line that runs `cmd` with HEARTH_MASTER_KEY read from the
  node's 0600 file, so the key never appears in a command line or a log."
  [cmd]
  (str "HEARTH_MASTER_KEY=$(cat " root "/master_key) && export HEARTH_MASTER_KEY"
       " && exec " cmd))

(defn- install!
  "Phase 1 on one node: a clean /opt/hearth with the binary, the node's
  bundle and the start script, and a config that validates."
  [test node material]
  (let [bundle (str material "/nodes/" node)]
    (c/exec :rm :-rf root)
    (c/exec :mkdir :-p (str root "/tls"))
    (c/exec :chmod "0700" root)
    (c/upload (:binary test) binary)
    (c/exec :chmod "0755" binary)
    ; One file per upload: the SSHJ remote uploads a single file per call.
    (doseq [f    ["hearth.yaml" "seed.yaml" "master_key" "tls/ca.crt"
                  "tls/peer.crt" "tls/peer.key" "tls/https.crt" "tls/https.key"]
            :let [local (io/file bundle f)]
            ; seed.yaml is only in the primary's bundle.
            :when (.isFile local)]
      (c/upload local (str root "/" f)))
    (c/exec :chmod "0600" (str root "/master_key") config
            (str root "/tls/peer.key") (str root "/tls/https.key"))
    (cu/write-file! (str "#!/bin/sh\n"
                         (with-master-key (str binary " serve --config " config))
                         "\n")
                    start-script)
    (c/exec :chmod "0700" start-script)
    (c/exec :bash :-c (with-master-key (str binary " config validate " config)))
    (info node "installed; hearth config validate OK")))

(defn- seed!
  "Phase 2 on the primary: seeds one store and mints the operator token into
  it. Returns the token. The tarball of the store lands in `material`."
  [node material password]
  (c/upload "scripts/seed-store.sh" (str root "/seed-store.sh"))
  (c/exec :chmod "0700" (str root "/seed-store.sh"))
  (let [token (c/exec (cc/env {:HEARTH            binary
                              :SEED_CONFIG       (str root "/seed.yaml")
                              :SEED_DATA_DIR     seed-dir
                              :SEED_URL          (node-url node)
                              :SEED_CA           (str root "/tls/ca.crt")
                              :SEED_LOG          seed-log
                              :OPERATOR_EMAIL    operator-email
                              :OPERATOR_PASSWORD password
                              :TOKEN_TTL         "1h"})
                      :bash :-c (with-master-key (str root "/seed-store.sh")))]
    (when (str/blank? token)
      (throw (ex-info "seed-store.sh printed no token" {:type ::setup-error})))
    (c/exec :tar :-C seed-dir :-czf (str root "/seed.tgz") ".")
    (c/download (str root "/seed.tgz") (str material "/seed.tgz"))
    (info node "seeded the store and minted the operator token")
    (str/trim token)))

(defn- populate!
  "Phase 3 on one node: the data directory becomes a copy of the seed."
  [material]
  (c/upload (str material "/seed.tgz") (str root "/seed.tgz"))
  (c/exec :rm :-rf data-dir)
  (c/exec :mkdir :-p data-dir)
  (c/exec :chmod "0700" data-dir)
  (c/exec :tar :-C data-dir :-xzf (str root "/seed.tgz"))
  (c/exec :rm :-f (str root "/seed.tgz")))

(defn start!*
  "Starts hearth on the current node from its data directory."
  []
  (cu/start-daemon! {:logfile log-file
                     :pidfile pid-file
                     :chdir   root
                     :exec    binary}
                    start-script))

(defn kill!*
  "Kills hearth on the current node with SIGKILL."
  []
  (cu/stop-daemon! binary pid-file 9))

(defn ready?
  "True when the current node answers /readyz over HTTPS. A node opens HTTP
  only after its start-up writes found a leader."
  [node]
  (try (c/exec :curl :-fsS :-o "/dev/null" :--max-time 2
               :--cacert (str root "/tls/ca.crt")
               (str (node-url node) "/readyz"))
       true
       (catch Exception _ false)))

(defn await-ready!
  "Blocks until the current node answers /readyz, up to `timeout-ms`."
  [node timeout-ms]
  (util/await-fn (fn [] (when-not (ready? node)
                          (throw (ex-info "not ready" {})))
                   true)
                 {:timeout        timeout-ms
                  :retry-interval 500
                  :log-interval   10000
                  :log-message    (str "waiting for " node " /readyz")}))

(declare cluster-status)

(defrecord HearthDB [state]
  db/DB
  (setup! [_ test node]
    (let [material (:material @state)]
      (install! test node material)
      (jepsen/synchronize test)
      (when (= node (jepsen/primary test))
        (swap! state assoc :token (seed! node material (:password @state))))
      (jepsen/synchronize test 120)
      (populate! material)
      (jepsen/synchronize test)
      (start!*)
      ; The start-up write window is 120 s; a node opens HTTP after it.
      (await-ready! node 150000)
      (info node "ready")
      (jepsen/synchronize test 180)))

  (teardown! [_ test node]
    (kill!*)
    (c/exec :rm :-rf root))

  db/Kill
  (start! [_ test node] (start!*))
  (kill! [_ test node] (kill!*))

  db/Primary
  ; The nodes that report role "leader". The :primaries partition isolates
  ; them. During an election there may be none; then one node at random, so
  ; the fault still happens and the history records which node it hit.
  (primaries [this test]
    (let [leaders (->> (:nodes test)
                       (filter #(= "leader" (get-in (cluster-status this %)
                                                    [:body "role"])))
                       vec)]
      (if (seq leaders)
        leaders
        (do (warn "no node reports role leader; isolating a random node")
            [(rand-nth (:nodes test))]))))
  (setup-primary! [_ test node])

  db/LogFiles
  (log-files [_ test node]
    (cond-> {log-file "hearth.log"}
      (= node (jepsen/primary test)) (assoc seed-log "seed.log"))))

(defn hearth-db
  "A hearth DB for `nodes`. Verifies the binary and generates the run's
  material now, so a bad binary stops the run before any node is touched."
  [opts]
  (verify-binary! (:binary opts))
  (->HearthDB (atom {:material (gen-material! (:nodes opts))
                     :password (str "jepsen-" (random-uuid))
                     :token    nil})))

(defn operator-token
  "The system-realm token seeded into the store; nil before setup."
  [db]
  (:token @(:state db)))

(defn ca-cert
  "The path of the run's CA certificate on the control node."
  [db]
  (str (:material @(:state db)) "/ca.crt"))

(defn http-client
  "The db's HTTPS client, which trusts the run's CA. Built on first use."
  [db]
  (or (:client @(:state db))
      (:client (swap! (:state db)
                      #(if (:client %) % (assoc % :client (http/client (ca-cert db))))))))

(defn cluster-status
  "GET /admin/cluster/status on `node` with the operator token, as an
  http/request! result."
  [db node]
  (http/request! (http-client db) (str (node-url node) "/admin/cluster/status")
                 {:headers {"Authorization" (str "Bearer " (operator-token db))
                            "X-Realm-ID"    system-realm}
                  :timeout 5000}))
