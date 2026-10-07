(ns jepsen.hearth.core
  "Entry point: `lein run test --workload <name> --nemesis <faults>` inside
  the control container. See README.md."
  (:gen-class)
  (:require [clojure.string :as str]
            [clojure.tools.logging :refer [error info]]
            [jepsen [checker :as checker]
                    [cli :as cli]
                    [core :as jepsen]
                    [generator :as gen]
                    [nemesis :as n]
                    [store :as store]
                    [tests :as tests]]
            [jepsen.hearth [audit :as audit]
                           [converge :as converge]
                           [db :as hdb]
                           [nemesis :as hn]
                           [register :as register]
                           [replace :as replace]
                           [revocation :as revocation]
                           [same-node :as same-node]
                           [runner :as runner]
                           [set :as hset]
                           [single-use :as single-use]
                           [snapshot :as snapshot]
                           [staleness :as staleness]]))

(def workloads
  "Workload name -> function of the CLI options and the db that returns the
  workload's part of the test: :client, :generator (client ops during the
  faults), :final-generator (client reads after the heal) and :checker. Any
  may be nil. A workload that must time its own faults returns
  :combined-generator (client and nemesis ops) instead of :generator; the
  random fault schedule then does not run, the heal phase still does. A
  workload with a fault of its own returns :nemesis (composed with the
  package's) and :nemesis-generator (mixed into the fault schedule)."
  {"noop" (fn [_opts _db]
            ; No client operations: proves setup, teardown, log collection,
            ; the faults and the convergence check (tasks 2.2, 2.4, 2.5).
            {})
   "set"      hset/workload
   "register" register/workload
   "single-use" single-use/workload
   "same-node"  same-node/workload
   "revocation" revocation/workload
   "revocation-isolated" revocation/isolated-workload
   "staleness"  staleness/workload
   "audit"      audit/workload
   "snapshot"   snapshot/workload
   "replace"    replace/workload})

(def catalog
  "The suite: test name -> the options that define it. Each name has an
  entry in expectations.edn."
  {"noop" {:workload "noop" :nemesis []}
   ; W1, W2 (CONSISTENCY.md section 9): partitions and kill -9.
   "set"  {:workload "set" :nemesis [:partition :kill]}
   ; W1, W2, W3: partitions, kill -9 and restart.
   "register" {:workload "register" :nemesis [:partition :partition-leader :kill]}
   ; W4: partitions and kill -9.
   "single-use" {:workload "single-use" :nemesis [:partition :kill]}
   ; R1: partitions, including one that isolates the leader.
   "same-node"  {:workload "same-node" :nemesis [:partition :partition-leader]}
   ; V1: delay on the peer links.
   "revocation" {:workload "revocation" :nemesis [:packet]}
   ; V2 (xfail G1): the same rounds under partitions. A node cut off from
   ; the cluster never learns of the revocation and goes on accepting the
   ; session after the bound; V2 says it must answer unavailable instead.
   "revocation-isolated" {:workload "revocation-isolated" :nemesis [:partition]}
   ; R2 (xfail G1): reads on every node while a minority or the leader is
   ; cut off. A cut-off node goes on serving its older data after
   ; read_lag_threshold_ms; R2 says it must answer unavailable instead.
   "staleness"  {:workload "staleness" :nemesis [:partition :partition-leader]}
   ; W7 (xfail G4): audited admin changes on every node at once. Two nodes
   ; can chain an event from the same head, and the chain stops verifying.
   "audit"      {:workload "audit" :nemesis []}
   ; R3, R4 (xfail G2): reads on a node while it installs a snapshot. The
   ; install deletes every key before it writes the snapshot, and reads are
   ; not fenced meanwhile. The workload times its own partition. With the
   ; default read_lag_threshold_ms the lag monitor happens to fence reads
   ; within 50 ms of the snapshot's arrival, before the restore deletes a
   ; key; this test raises it, so only a fence of the install itself (the G2
   ; fix) makes it pass.
   "snapshot"   {:workload "snapshot" :nemesis [:partition]
                 :read-lag-threshold-ms 3600000}
   ; Section 6 (xfail G9): the set workload while the lowest Raft ID is
   ; replaced with an empty data directory under its old ID.
   "replace"    {:workload "replace" :nemesis [:partition]}})

(def ssh-key
  "The key pair the control container generates; the nodes trust it."
  "/keys/id_ed25519")

(defn test-name
  "hearth-<workload>, plus the faults it uses: each test names them."
  [opts]
  (str "hearth-" (:workload opts)
       (when (seq (:nemesis opts))
         (str "-" (str/join "+" (map name (:nemesis opts)))))))

(defn hearth-test
  "Builds a Jepsen test map from the parsed CLI options."
  [opts]
  (let [db       (hdb/hearth-db opts)
        pkg      (hn/package {:db                  db
                              :fault-names         (:nemesis opts)
                              :interval            (:nemesis-interval opts)
                              :recovery-timeout-ms (* 1000 (:recovery-timeout opts))})
        workload ((workloads (:workload opts)) opts db)]
    (merge tests/noop-test
           opts
           (when-let [c (:client workload)] {:client c})
           {:name      (test-name opts)
            ; The V1 bound's injected delay (Open Question 5).
            :v1-delay-ms (hn/injected-delay-ms (:nemesis opts))
            :db        db
            :nemesis   (if-let [own (:nemesis workload)]
                         (n/compose [(:nemesis pkg) own])
                         (:nemesis pkg))
            ; The CLI sets :private-key-path to nil when the flag is absent.
            :ssh       (update (:ssh opts) :private-key-path #(or % ssh-key))
            :plot      {:nemeses (:perf pkg)}
            :generator (gen/phases
                         (gen/time-limit (:time-limit opts)
                                         (or (:combined-generator workload)
                                             (gen/nemesis (if-let [own (:nemesis-generator workload)]
                                                            (gen/any (:generator pkg) own)
                                                            (:generator pkg))
                                                          (:generator workload))))
                         (gen/nemesis (:final-generator pkg))
                         ; Clients only: each-thread would otherwise give the
                         ; nemesis thread its own copy of the final reads.
                         (gen/clients (:final-generator workload)))
            :checker   (checker/compose
                         (cond-> {:converge (converge/checker)}
                           (:checker workload)
                           (assoc :workload (:checker workload)
                                  :perf     (checker/perf {:nemeses (:perf pkg)})
                                  :stats    (checker/stats))))})))

(def cli-opts
  "Options on top of Jepsen's standard ones."
  [[nil "--binary PATH" "hearth binary built by `make jepsen-binary`."
    :default "docker/.build/hearth"]
   ["-w" "--workload NAME" "Workload to run."
    :default "noop"
    :validate [workloads (str "must be one of " (sort (keys workloads)))]]
   [nil "--nemesis FAULTS"
    (str "Comma-separated faults: " (str/join ", " (map name (sort (keys hn/faults))))
         ". Empty for none.")
    :default []
    :parse-fn hn/parse-faults
    :validate [#(every? hn/faults %) "unknown fault"]]
   [nil "--nemesis-interval SECONDS" "Seconds between fault operations."
    :default 10
    :parse-fn parse-long
    :validate [pos? "must be positive"]]
   [nil "--recovery-timeout SECONDS"
    "How long the nodes may take to agree on last_applied_index after the heal."
    :default 60
    :parse-fn parse-long
    :validate [pos? "must be positive"]]])

(defn- run-one
  "Runs catalog test `test-name` with `options`. A setup error is a result,
  not a crash, so the rest of the suite still runs."
  [test-name options]
  (try
    (let [t (jepsen/run! (hearth-test (merge options (catalog test-name))))]
      {:test   test-name
       :valid? (:valid? (:results t))
       :store  (str (store/path t))})
    (catch Exception e
      (error e "setup or run error in" test-name)
      {:test   test-name
       :valid? :unknown
       :reason (str "setup or run error, not a consistency result: " (.getMessage e))})))

(defn- run-suite
  "Runs the selected catalog tests, classifies them against
  expectations.edn, prints the report and exits 1 when any test failed."
  [{:keys [options]}]
  (let [names (or (seq (:only options)) (sort (keys catalog)))
        runs  (mapv #(run-one % options) names)
        v     (runner/verdict (runner/load-expectations "expectations.edn") runs)]
    (info (str "Suite results:\n" (runner/report v)))
    (println (runner/report v))
    (System/exit (:exit v))))

(def suite-opts
  "Options of the suite command on top of Jepsen's and ours."
  [[nil "--only NAMES" "Comma-separated catalog tests to run (default: all)."
    :default []
    :parse-fn #(vec (remove str/blank? (map str/trim (str/split % #","))))
    :validate [#(every? catalog %) (str "must be among " (sort (keys catalog)))]]])

(defn -main
  "Runs the CLI: `test` runs one test from flags, `suite` runs catalog
  tests and classifies them."
  [& args]
  (cli/run! (merge (cli/single-test-cmd {:test-fn  hearth-test
                                         :opt-spec cli-opts})
                   {"suite" {:opt-spec (cli/merge-opt-specs cli/test-opt-spec
                                                            (into cli-opts suite-opts))
                             :opt-fn   cli/test-opt-fn
                             :usage    "Usage: lein run suite [--only NAMES] [OPTIONS ...]"
                             :run      run-suite}}
                   (cli/serve-cmd))
            args))
