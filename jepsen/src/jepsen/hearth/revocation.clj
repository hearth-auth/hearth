(ns jepsen.hearth.revocation
  "The revocation workload (V1; design decision 7): a client revokes a
  session on one node; clients on every node validate it in a loop. A
  :validate op carries the node's answer in :active?.

  Checker: after the revocation completes, no validation that starts later
  than the V1 bound accepts the session. The bound (Open Question 5) is
  400 ms + 2 x the injected one-way peer delay + 1 s slack, and each result
  records it."
  (:require [jepsen.checker :as checker]
            [jepsen.history :as h]))

(defn bound-ms
  "The V1 bound for an injected one-way peer delay of `delay-ms`."
  [delay-ms]
  (+ 400 (* 2 delay-ms) 1000))

(def ^:private ns-per-ms 1000000)

(defn checker
  "Valid when every session was rejected by every validation invoked more
  than the bound after its :ok revocation completed, and at least one
  revocation succeeded. The test map's :v1-delay-ms is the injected delay."
  []
  (reify checker/Checker
    (check [_ test history _opts]
      (let [bound    (bound-ms (:v1-delay-ms test 0))
            revoked  (into {}
                           (comp (filter #(and (= :revoke (:f %)) (= :ok (:type %))))
                                 (map (juxt :value :time)))
                           history)
            late     (vec (for [op    (filter #(and (= :validate (:f %)) (= :ok (:type %))
                                                    (:active? %))
                                              history)
                                :let  [done  (revoked (:value op))
                                       start (:time (h/invocation history op))]
                                :when (and done start
                                           (< (* bound ns-per-ms) (- start done)))]
                            {:session  (:value op)
                             :node     (:node op)
                             :after-ms (quot (- start done) ns-per-ms)}))]
        (cond
          (empty? revoked)
          {:valid?   false
           :bound-ms bound
           :error    "no revocation succeeded; the run proves nothing"}

          (seq late)
          {:valid?   false
           :bound-ms bound
           :late     late
           :error    "a node accepted a revoked session after the V1 bound"}

          :else
          {:valid? true :bound-ms bound :revoked (count revoked)})))))
