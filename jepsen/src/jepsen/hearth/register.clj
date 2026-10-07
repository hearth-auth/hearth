(ns jepsen.hearth.register
  "The register workload (W1, W2, W3; design decision 7): one mutable user
  field per key. Clients write during the faults; after the heal every node
  reads every key once.

  Checkers: Knossos over the writes plus the final reads, per key (a write
  that ends :info may or may not have happened, W3), and `agree-checker`:
  every node read every key, and all nodes read the same value. Knossos
  alone cannot see a disagreement that an unknown write could explain."
  (:require [jepsen [checker :as checker]
                    [independent :as independent]]
            [knossos.model :as model]))

(defn agree-checker
  "Valid when every node has a final read of every written key and, per key,
  all those reads return the same value. A node's final read of a key is its
  last :ok read of it; each read carries the :node it ran on."
  []
  (reify checker/Checker
    (check [_ test history _opts]
      (let [ks       (into (sorted-set)
                           (comp (filter #(= :write (:f %)))
                                 (map (comp key :value)))
                           history)
            finals   (reduce (fn [m op]
                               (let [[k v] (:value op)]
                                 (assoc-in m [k (:node op)] v)))
                             {}
                             (filter #(and (= :read (:f %)) (= :ok (:type %)))
                                     history))
            unread   (into (sorted-map)
                           (keep (fn [k]
                                   (let [missing (vec (remove (get finals k {})
                                                              (:nodes test)))]
                                     (when (seq missing) [k missing]))))
                           ks)
            disagree (into (sorted-map)
                           (keep (fn [[k by-node]]
                                   (when (< 1 (count (set (vals by-node))))
                                     [k (into (sorted-map) by-node)])))
                           finals)]
        {:valid?   (and (empty? unread) (empty? disagree))
         :keys     (count ks)
         :unread   unread
         :disagree disagree}))))

(defn checker
  "Knossos per key, plus `agree-checker`. The model starts at nil: a key
  whose writes all failed reads as nil."
  []
  (checker/compose
    {:linear (independent/checker
               (checker/linearizable {:model     (model/register nil)
                                      :algorithm :linear}))
     :agree  (agree-checker)}))
