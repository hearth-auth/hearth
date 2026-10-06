(ns jepsen.hearth.converge
  "The heal-and-converge phase (design decision 8; spec \"Final reads follow
  a heal\"). After the faults heal, a :converge op waits until every node
  reports the same last_applied_index in GET /admin/cluster/status. The
  checker marks a test invalid when that never happened, and names the
  nodes that stayed behind."
  (:require [clojure.string :as str]
            [clojure.tools.logging :refer [info warn]]
            [jepsen [checker :as checker]
                    [nemesis :as nemesis]]
            [jepsen.hearth.db :as hdb]))

(def default-recovery-timeout-ms
  "How long the nodes may take to agree after the heal."
  60000)

(defn- sweep
  "One poll of every node: node -> last_applied_index, or, when the node gave
  no index, whatever `fetch` returned instead (nil or the reason)."
  [fetch nodes]
  (into (sorted-map) (map (fn [n] [n (fetch n)])) nodes))

(defn- lagging
  "Nodes that gave no index, or are behind the highest index of the sweep."
  [indices]
  (let [known (filter integer? (vals indices))
        top   (when (seq known) (apply max known))]
    (vec (for [[n i] indices :when (or (not (integer? i)) (< i top))] n))))

(defn await-convergence
  "Polls (fetch node) on every node until all return the same index, or
  until :timeout-ms passes. Returns {:converged? true :index i :indices m} or
  {:converged? false :lagging [nodes] :indices m}, with m the last sweep."
  [fetch nodes {:keys [timeout-ms interval-ms]
                :or   {timeout-ms  default-recovery-timeout-ms
                       interval-ms 500}}]
  (let [deadline (+ (System/nanoTime) (* 1000000 (long timeout-ms)))]
    (loop []
      (let [indices (sweep fetch nodes)
            behind  (lagging indices)]
        (cond
          (empty? behind)
          {:converged? true :index (val (first indices)) :indices indices}

          (<= deadline (System/nanoTime))
          {:converged? false :lagging behind :indices indices}

          :else
          (do (Thread/sleep (long interval-ms))
              (recur)))))))

(defn checker
  "Valid only when every :converge op in the history converged. A history
  without one is invalid: its final reads followed no heal."
  []
  (reify checker/Checker
    (check [_ _test history _opts]
      ; Jepsen records a nemesis invocation as :info with a nil value, like
      ; its completion. Only a completion carries the result map.
      (let [results (->> history
                         (filter #(= :converge (:f %)))
                         (map :value)
                         (filter #(and (map? %) (contains? % :converged?))))
            failed  (remove :converged? results)
            behind  (vec (distinct (mapcat :lagging failed)))]
        (cond
          (empty? results)
          {:valid? false
           :error  "no :converge op completed; the final reads followed no heal"}

          (seq failed)
          {:valid?  false
           :lagging behind
           :indices (:indices (first failed))
           :error   (str "nodes did not converge on last_applied_index"
                         " within the recovery timeout: "
                         (str/join ", " behind))}

          :else
          {:valid? true})))))

(defn status-fetcher
  "A fetch function for `await-convergence` that reads last_applied_index
  from GET /admin/cluster/status. When a node gives no index, it returns the
  reason: the status and body, or the client error."
  [db]
  (fn [node]
    (let [r (hdb/cluster-status db node)]
      (or (when (= 200 (:status r))
            (get-in r [:body "last_applied_index"]))
          (:error r)
          {:status (:status r) :body (:body r)}))))

(defn nemesis
  "Handles {:f :converge}: waits for every node to reach the same
  last_applied_index. Compose it with the fault nemeses."
  [opts]
  (reify
      nemesis/Reflection
      (fs [_] #{:converge})

      nemesis/Nemesis
      (setup! [this _test] this)

      (invoke! [_ test op]
        (let [fetch  (status-fetcher (:db test))
              result (await-convergence
                       fetch (:nodes test)
                       {:timeout-ms (:recovery-timeout-ms
                                      opts default-recovery-timeout-ms)})]
          (if (:converged? result)
            (info "nodes converged at last_applied_index" (:index result))
            (warn "nodes did not converge:" (:lagging result) (:indices result)))
          (assoc op :type :info :value result)))

      (teardown! [_ _test])))
