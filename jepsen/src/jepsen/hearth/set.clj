(ns jepsen.hearth.set
  "The set workload (W1, W2; design decision 7): clients add unique items,
  and after the heal every node reads the full set once.

  Checkers: Jepsen's set-full over the history, plus `every-node-checker`,
  which reads each node's final read on its own. set-full calls an element
  lost only when its last absent read follows its last present read, so a
  node that misses an add can hide behind a later read on another node."
  (:require [clojure.set :as set]
            [jepsen.checker :as checker]))

(defn- values
  "The :value of every op with this :f and :type."
  [history f type]
  (into #{}
        (comp (filter #(and (= f (:f %)) (= type (:type %))))
              (map :value))
        history))

(defn every-node-checker
  "Valid when every node in the test has a final read, every final read holds
  every :ok add, and no final read holds a :fail add. A node's final read is
  its last :ok read; each read carries the :node it ran on."
  []
  (reify checker/Checker
    (check [_ test history _opts]
      (let [acked      (values history :add :ok)
            failed     (values history :add :fail)
            finals     (->> history
                            (filter #(and (= :read (:f %)) (= :ok (:type %))))
                            (group-by :node)
                            (into {} (map (fn [[node reads]]
                                            [node (set (:value (last reads)))]))))
            unread     (vec (remove finals (:nodes test)))
            missing    (into (sorted-map)
                             (keep (fn [[node xs]]
                                     (let [m (set/difference acked xs)]
                                       (when (seq m) [node m]))))
                             finals)
            unexpected (set/intersection failed (reduce set/union #{} (vals finals)))]
        {:valid?       (and (empty? unread) (empty? missing) (empty? unexpected))
         :acknowledged (count acked)
         :unread       unread
         :missing      missing
         :unexpected   unexpected}))))

(defn checker
  "set-full plus the per-node check."
  []
  (checker/compose {:set-full   (checker/set-full)
                    :every-node (every-node-checker)}))
