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
                    [store :as store]
                    [tests :as tests]]
            [jepsen.hearth [converge :as converge]
                           [db :as hdb]
                           [nemesis :as hn]
                           [runner :as runner]]))

(def workloads
  "Workload name -> function of the CLI options that returns the workload's
  part of the test: :generator (client ops during the faults),
  :final-generator (client reads after the heal) and :checker. Any may be
  nil."
  {"noop" (fn [_opts]
            ; No client operations: proves setup, teardown, log collection,
            ; the faults and the convergence check (tasks 2.2, 2.4, 2.5).
            {})})

(def catalog
  "The suite: test name -> the options that define it. Each name has an
  entry in expectations.edn."
  {"noop" {:workload "noop" :nemesis []}})

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
