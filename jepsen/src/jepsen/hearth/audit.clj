(ns jepsen.hearth.audit
  "The audit-chain workload (W7, xfail G4; design decision 7): every client
  makes audited admin changes on its own node at the same time; after the
  run, every node verifies the realm's audit hash chain once.

  Checker: the chain verifies on every node. With G4 open, two nodes can
  chain an event from the same head, so the test is xfail."
  (:require [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.hearth [admin :as admin]
                           [http :as http]]))

(defrecord Client [db node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test] (admin/session! db test))

  (invoke! [_ _test op]
    (case (:f op)
      ; Creating a user is an audited admin change.
      :change (http/complete op :write
                             (admin/request! db node "/admin/users"
                                             {:method :post
                                              :json   {"email"        (str "w7-" (:value op)
                                                                           "@jepsen.test")
                                                       "display_name" "w7"}}))
      :verify (let [r (admin/request! db node "/admin/audit/verify" {:method :post})]
                (if (= 200 (:status r))
                  (assoc op :type :ok :node node
                         :value {:ok          (get-in r [:body "ok"])
                                 :event-count (get-in r [:body "event_count"])})
                  (assoc (http/complete op :read r) :node node)))))

  (teardown! [_ _test])
  (close! [_ _test]))

(declare checker)

(defn workload
  "Every client thread (one per node) creates users on its own node; after
  the run, each verifies the audit chain on its node until a verification
  succeeds, for at most 120 s."
  [_opts db]
  {:client          (->Client db nil)
   :generator       (->> (range)
                         (map (fn [x] {:f :change :value x}))
                         (gen/stagger 1/20))
   :final-generator (gen/time-limit 120
                                    (gen/each-thread
                                      (gen/until-ok
                                        (gen/stagger 1 (gen/repeat {:f :verify})))))
   :checker         (checker)})

(defn checker
  "Valid when at least one change was acknowledged (a run with none proves
  nothing), every node in the test has a final verification, and every
  final verification found the chain intact. A node's final verification is
  its last :ok :verify; each carries the :node it ran on."
  []
  (reify checker/Checker
    (check [_ test history _opts]
      (let [changed    (count (filter #(and (= :change (:f %)) (= :ok (:type %))) history))
            finals     (into {}
                             (comp (filter #(and (= :verify (:f %)) (= :ok (:type %))))
                                   (map (juxt :node :value)))
                             history)
            unverified (vec (remove finals (:nodes test)))
            broken     (vec (sort (keep (fn [[node v]] (when-not (true? (:ok v)) node))
                                        finals)))]
        (cond
          (zero? changed)
          {:valid? false
           :error  "no admin change was acknowledged; the run proves nothing"}

          (or (seq unverified) (seq broken))
          {:valid?     false
           :changed    changed
           :unverified unverified
           :broken     broken
           :finals     (into (sorted-map) finals)
           :error      "the audit chain does not verify on every node"}

          :else
          {:valid? true :changed changed :finals (into (sorted-map) finals)})))))
