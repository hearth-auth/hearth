(ns jepsen.hearth.core
  "Entry point: `lein run test --workload <name>` inside the control
  container. See README.md."
  (:gen-class)
  (:require [jepsen [checker :as checker]
                    [cli :as cli]
                    [generator :as gen]
                    [tests :as tests]]
            [jepsen.hearth [converge :as converge]
                           [db :as hdb]]))

(def workloads
  "Workload name -> function of the CLI options that returns the workload's
  part of the test map."
  {"noop" (fn [_opts]
            ; No client operations and no faults: proves setup, teardown, log
            ; collection and the convergence check on every node (2.2, 2.4).
            {:generator (gen/nemesis (gen/once {:type :info :f :converge}))
             :checker   (checker/compose {:converge (converge/checker)})})})

(def ssh-key
  "The key pair the control container generates; the nodes trust it."
  "/keys/id_ed25519")

(defn hearth-test
  "Builds a Jepsen test map from the parsed CLI options."
  [opts]
  (let [workload ((workloads (:workload opts)) opts)]
    (merge tests/noop-test
           opts
           {:name (str "hearth-" (:workload opts))
            :db   (hdb/hearth-db opts)
            :nemesis (converge/nemesis
                       {:recovery-timeout-ms (* 1000 (:recovery-timeout opts))})
            ; The CLI sets :private-key-path to nil when the flag is absent.
            :ssh  (update (:ssh opts) :private-key-path #(or % ssh-key))}
           workload)))

(def cli-opts
  "Options on top of Jepsen's standard ones."
  [[nil "--binary PATH" "hearth binary built by `make jepsen-binary`."
    :default "docker/.build/hearth"]
   ["-w" "--workload NAME" "Workload to run."
    :default "noop"
    :validate [workloads (str "must be one of " (sort (keys workloads)))]]
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
