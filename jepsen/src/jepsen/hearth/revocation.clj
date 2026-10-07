(ns jepsen.hearth.revocation
  "The revocation workload (V1; design decision 7): a client revokes a
  session on one node; clients on every node validate it in a loop. A
  :validate op carries the node's answer in :active?.

  Checker: after the revocation completes, no validation that starts later
  than the V1 bound accepts the session. The bound (Open Question 5) is
  400 ms + 2 x the injected one-way peer delay + 1 s slack, and each result
  records it."
  (:require [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.history :as h]
            [jepsen.hearth [admin :as admin]
                           [auth :as auth]
                           [db :as hdb]
                           [http :as http]]))

(defn bound-ms
  "The V1 bound for an injected one-way peer delay of `delay-ms`."
  [delay-ms]
  (+ 400 (* 2 delay-ms) 1000))

(def ^:private ns-per-ms 1000000)

(defn checker
  "Valid when every session was rejected by every validation invoked more
  than the bound after its :ok revocation completed, at least one
  revocation succeeded, and at least one validation saw a live session (the
  control: a probe that rejects everything proves nothing). The test map's
  :v1-delay-ms is the injected delay."
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

          (not-any? #(and (= :validate (:f %)) (= :ok (:type %)) (:active? %)) history)
          {:valid?   false
           :bound-ms bound
           :error    "the probe never saw a live session; the run proves nothing"}

          (seq late)
          {:valid?   false
           :bound-ms bound
           :late     late
           :error    "a node accepted a revoked session after the V1 bound"}

          :else
          {:valid? true :bound-ms bound :revoked (count revoked)})))))

(def watch-seconds
  "How long every client validates a round's session after it is revoked:
  longer than the bound under the packet fault (1.9 s)."
  4)

(defn- validate!
  "GET /realms/<realm>/userinfo with the session's access token on `node`:
  validate_token, the hot path, which needs the session on that node."
  [db node access]
  (http/request! (hdb/http-client db)
                 (str (hdb/node-url node) "/realms/" hdb/realm "/userinfo")
                 {:headers {"Authorization" (str "Bearer " access)}}))

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))
  (setup! [_ test] (admin/session! db test))

  (invoke! [_ test op]
    (let [n (:value op)
          {:keys [round access session-id]} @state]
      (case (:f op)
        ; A fresh session for round n: the realm admin signs in again.
        :sign-in  (let [r (auth/sign-in-anywhere! db test node hdb/realm-admin-email
                                                  (hdb/realm-admin-password db))]
                    (if (:access r)
                      (do (reset! state {:round n :access (:access r)
                                         :session-id (:session-id r)})
                          (assoc op :type :ok :signed-in-on (:node r)))
                      (assoc op :type :fail :error (:error r))))

        :revoke   (if (= n round)
                    (http/complete op :write
                                   (admin/request! db node (str "/admin/sessions/" session-id)
                                                   {:method :delete}))
                    (assoc op :type :fail :error :no-session))

        :validate (if (= n round)
                    (let [r (validate! db node access)]
                      (case (:status r)
                        200 (assoc op :type :ok :node node :active? true)
                        401 (assoc op :type :ok :node node :active? false)
                        (assoc (http/complete op :read r) :node node)))
                    (assoc op :type :fail :error :no-session)))))

  (teardown! [_ _test])
  (close! [_ _test]))

(defn workload
  "Rounds: a client signs in (the victim session), every client thread (one
  per node) validates it once, a client revokes it, then every client
  thread validates it for `watch-seconds`."
  [_opts db]
  {:client    (->Client db (atom {}) nil)
   :generator (map (fn [n]
                     (gen/phases {:f :sign-in :value n}
                                 ; The control: the live session, on every node.
                                 (gen/each-thread {:f :validate :value n})
                                 {:f :revoke :value n}
                                 (gen/each-thread
                                   (gen/time-limit watch-seconds
                                                   (gen/stagger 1/10
                                                                (gen/repeat {:f :validate
                                                                             :value n}))))))
                   (range))
   :checker   (checker)})
