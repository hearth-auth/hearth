(ns jepsen.hearth.core
  "Entry point: `lein run test --workload <name>` inside the control
  container. See README.md."
  (:gen-class)
  (:require [jepsen [checker :as checker]
                    [cli :as cli]
                    [tests :as tests]]
            [jepsen.hearth.db :as hdb]))

(def workloads
  "Workload name -> function of the CLI options that returns the workload's
  part of the test map."
  {"noop" (fn [_opts]
            ; No client operations and no faults: proves setup, teardown and
            ; log collection on every node (task 2.2).
            {:generator nil
             :checker   (checker/unbridled-optimism)})})

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
            ; The CLI sets :private-key-path to nil when the flag is absent.
            :ssh  (update (:ssh opts) :private-key-path #(or % ssh-key))}
           workload)))

(def cli-opts
  "Options on top of Jepsen's standard ones."
  [[nil "--binary PATH" "hearth binary built by `make jepsen-binary`."
    :default "docker/.build/hearth"]
   ["-w" "--workload NAME" "Workload to run."
    :default "noop"
    :validate [workloads (str "must be one of " (sort (keys workloads)))]]])

(defn -main
  "Runs the CLI."
  [& args]
  (cli/run! (merge (cli/single-test-cmd {:test-fn  hearth-test
                                         :opt-spec cli-opts})
                   (cli/serve-cmd))
            args))
