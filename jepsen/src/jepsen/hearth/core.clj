(ns jepsen.hearth.core
  "Entry point: `lein run test --workload <name> --nemesis <faults>` inside
  the control container. See README.md."
  (:gen-class)
  (:require [clojure.string :as str]
            [jepsen [checker :as checker]
                    [cli :as cli]
                    [generator :as gen]
                    [tests :as tests]]
            [jepsen.hearth [converge :as converge]
                           [db :as hdb]
                           [nemesis :as hn]]))

(def workloads
  "Workload name -> function of the CLI options that returns the workload's
  part of the test: :generator (client ops during the faults),
  :final-generator (client reads after the heal) and :checker. Any may be
  nil."
  {"noop" (fn [_opts]
            ; No client operations: proves setup, teardown, log collection,
            ; the faults and the convergence check (tasks 2.2, 2.4, 2.5).
            {})})

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
        workload ((workloads (:workload opts)) opts)]
    (merge tests/noop-test
           opts
           {:name      (test-name opts)
            :db        db
            :nemesis   (:nemesis pkg)
            ; The CLI sets :private-key-path to nil when the flag is absent.
            :ssh       (update (:ssh opts) :private-key-path #(or % ssh-key))
            :plot      {:nemeses (:perf pkg)}
            :generator (gen/phases
                         (gen/time-limit (:time-limit opts)
                                         (gen/nemesis (:generator pkg)
                                                      (:generator workload)))
                         (gen/nemesis (:final-generator pkg))
                         (:final-generator workload))
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

(defn -main
  "Runs the CLI."
  [& args]
  (cli/run! (merge (cli/single-test-cmd {:test-fn  hearth-test
                                         :opt-spec cli-opts})
                   (cli/serve-cmd))
            args))
