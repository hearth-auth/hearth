(ns jepsen.hearth.single-use
  "The single-use workload (W4; design decision 7, Open Question 3): clients
  on several nodes redeem the same refresh token at POST /oauth/token. Each
  :ok answer carries the next token, the next artifact. The history names an
  artifact by its place in the chain (0, 1, 2 ...), never by the token.

  Checker: at most one :ok redemption per artifact."
  (:require [jepsen.checker :as checker]))

(defn checker
  "Valid when no artifact has two :ok redemptions and at least one
  redemption succeeded (a run with none proves nothing)."
  []
  (reify checker/Checker
    (check [_ _test history _opts]
      (let [oks        (->> history
                            (filter #(and (= :redeem (:f %)) (= :ok (:type %))))
                            (map :value)
                            frequencies)
            duplicates (into (sorted-map) (filter (fn [[_ n]] (< 1 n))) oks)]
        (cond
          (empty? oks)
          {:valid? false
           :error  "no redemption succeeded; the run proves nothing"}

          (seq duplicates)
          {:valid?     false
           :redeemed   (count oks)
           :duplicates duplicates
           :error      "an artifact was redeemed more than once"}

          :else
          {:valid? true :redeemed (count oks)})))))
