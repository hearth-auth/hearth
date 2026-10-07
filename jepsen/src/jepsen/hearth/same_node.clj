(ns jepsen.hearth.same-node
  "The same-node read workload (R1; design decision 7): each client is pinned
  to one node and owns one key. One :write-read op writes a new value there,
  then reads the key back on the same node. An :ok op carries the value its
  read returned in :read.

  Checker: every :ok op read back the value it wrote."
  (:require [jepsen.checker :as checker]))

(defn checker
  "Valid when every :ok :write-read read its own write, and at least one did
  (a run with none proves nothing)."
  []
  (reify checker/Checker
    (check [_ _test history _opts]
      (let [oks   (filter #(and (= :write-read (:f %)) (= :ok (:type %))) history)
            stale (vec (for [op oks :when (not= (:value op) (:read op))]
                         {:node    (:node op)
                          :process (:process op)
                          :wrote   (:value op)
                          :read    (:read op)}))]
        (cond
          (empty? oks)
          {:valid? false
           :error  "no write was acknowledged; the run proves nothing"}

          (seq stale)
          {:valid?  false
           :checked (count oks)
           :stale   stale
           :error   "a read on the writing node missed the acknowledged write"}

          :else
          {:valid? true :checked (count oks)})))))
