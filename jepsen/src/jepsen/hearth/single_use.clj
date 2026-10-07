(ns jepsen.hearth.single-use
  "The single-use workload (W4; design decision 7, Open Question 3): clients
  on several nodes redeem the same refresh token at POST /oauth/token. Each
  :ok answer carries the next token, the next artifact. The history names an
  artifact by its place in the chain (0, 1, 2 ...), never by the token.

  Checker: at most one :ok redemption per artifact."
  (:require [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.hearth [auth :as auth]
                           [db :as hdb]
                           [http :as http]]))

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))
  (setup! [_ _test])

  (invoke! [_ test op]
    (let [n (:value op)]
      (case (:f op)
        ; One client signs the realm admin in; the refresh token is round
        ; n's artifact. Hearth revokes a token's whole grant family when the
        ; token is presented twice, so every round needs its own sign-in.
        ; A sign-in runs on one node; when this client's node fails, it
        ; tries the others, so a dead node does not waste the round.
        :sign-in (let [r (auth/sign-in-anywhere! db test node hdb/realm-admin-email
                                                 (hdb/realm-admin-password db))]
                   (if (:refresh r)
                     (do (reset! state {:round n :refresh (:refresh r)})
                         (assoc op :type :ok :signed-in-on (:node r)))
                     (assoc op :type :fail :error (:error r))))

        :redeem  (let [{:keys [round refresh]} @state]
                   (if (= n round)
                     (http/complete op :write (auth/redeem! db node refresh))
                     (assoc op :type :fail :error :no-artifact))))))

  (teardown! [_ _test])
  (close! [_ _test]))

(declare checker)

(defn workload
  "Rounds: one client signs in, then every client thread (one per node)
  redeems that round's refresh token once."
  [_opts db]
  {:client    (->Client db (atom {}) nil)
   :generator (map (fn [n]
                     (gen/phases {:f :sign-in :value n}
                                 (gen/each-thread {:f :redeem :value n})))
                   (range))
   :checker   (checker)})

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
