(ns jepsen.hearth.same-node
  "The same-node read workload (R1; design decision 7): each client is pinned
  to one node and owns one key. One :write-read op writes a new value there,
  then reads the key back on the same node. An :ok op carries the value its
  read returned in :read.

  Checker: every :ok op read back the value it wrote."
  (:require [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.hearth [admin :as admin]
                           [http :as http]
                           [register :as register]]))

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test]
    (admin/session! db test)
    (locking state
      (when-not (:users @state)
        (swap! state assoc :users
               (into {}
                     (for [n (:nodes test)]
                       (let [r (admin/request! db (first (:nodes test)) "/admin/users"
                                               {:method :post
                                                :json   {"email"        (str "r1-" n "@jepsen.test")
                                                         "display_name" "init"}})]
                         [n (or (get-in r [:body "id"])
                                (throw (ex-info "creating an R1 user failed"
                                                {:status (:status r) :body (:body r)})))])))))))

  (invoke! [_ _test op]
    (let [path  (str "/admin/users/" (get-in @state [:users node]))
          wrote (admin/request! db node path
                                {:method :patch
                                 :json   {"display_name" (register/render-value (:value op))}})
          op    (assoc op :node node)]
      (if-not (= 200 (:status wrote))
        (http/complete op :write wrote)
        (let [read (admin/request! db node path {})]
          (if (= 200 (:status read))
            (assoc op :type :ok
                   :read (register/parse-value (get-in read [:body "display_name"])))
            ; The write happened; the read that would check it did not.
            (assoc op :type :info :error {:read (:error (http/outcome :read read))}))))))

  (teardown! [_ _test])
  (close! [_ _test]))

(declare checker)

(defn workload
  "Each client writes a fresh value to its own node's user, then reads it
  back on the same node."
  [_opts db]
  {:client    (->Client db (atom {}) nil)
   :generator (->> (range)
                   (map (fn [n] {:f :write-read :value n}))
                   (gen/stagger 1/10))
   :checker   (checker)})

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
