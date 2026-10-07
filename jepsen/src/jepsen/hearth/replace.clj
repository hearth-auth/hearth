(ns jepsen.hearth.replace
  "The node-replacement workload (section 6, xfail G9; design decision 7):
  the set workload, while the partition faults run and, every
  `wipe-interval` seconds, one node is replaced: killed, its data directory
  emptied, and started again with the same Raft ID.

  Checker: the set checkers. Replacing a node this way discards its saved
  vote, and the lowest Raft ID self-initialises on an empty data directory,
  so the test is xfail. It wipes the lowest ID."
  (:require [clojure.tools.logging :refer [info]]
            [jepsen [control :as c]
                    [generator :as gen]
                    [nemesis :as n]]
            [jepsen.hearth [db :as hdb]
                           [set :as hset]]))

(def wipe-interval
  "Mean seconds between two replacements."
  40)

(defn wipe-target
  "The node with the lowest Raft ID: gen-configs.sh gives node nX the ID X."
  [test]
  (apply min-key #(parse-long (subs % 1)) (:nodes test)))

(defn- wipe!
  "On the current node: kill hearth, empty its data directory, start it."
  []
  (hdb/kill!*)
  (c/exec :rm :-rf hdb/data-dir)
  (c/exec :mkdir :-p hdb/data-dir)
  (c/exec :chmod "0700" hdb/data-dir)
  (hdb/start!*))

(defn wipe-nemesis
  "Handles {:f :wipe :value [node ...]}: replaces each node."
  []
  (reify
    n/Nemesis
    (setup! [this _test] this)
    (invoke! [_ test op]
      (info "replacing" (:value op) "with an empty data directory")
      (c/on-nodes test (:value op) (fn [_test _node] (wipe!)))
      (assoc op :type :info))
    (teardown! [_ _test])

    n/Reflection
    (fs [_] #{:wipe})))

(defn workload
  "The set workload, plus `wipe-nemesis` and its ops for the fault
  schedule."
  [opts db]
  (let [target (wipe-target opts)]
    (assoc (hset/workload opts db)
           :nemesis           (wipe-nemesis)
           :nemesis-generator (gen/stagger wipe-interval
                                           (repeat {:type :info :f :wipe :value [target]})))))
