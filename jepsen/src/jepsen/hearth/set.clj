(ns jepsen.hearth.set
  "The set workload (W1, W2; design decision 7): clients add unique items,
  and after the heal every node reads the full set once.

  Checkers: Jepsen's set-full over the history, plus `every-node-checker`,
  which reads each node's final read on its own. set-full calls an element
  lost only when its last absent read follows its last present read, so a
  node that misses an add can hide behind a later read on another node."
  (:require [clojure.set :as set]
            [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.hearth [admin :as admin]
                           [http :as http]]))

(defn- email
  "The user an add of item `x` creates."
  [x]
  (str "set-" x "@jepsen.test"))

(def ^:private item-pattern #"^set-(\d+)@jepsen\.test$")

(def page-size
  "Users per GET /admin/users page (the server's maximum)."
  100)

(defn read-items
  "Lists every user on `node`, page by page, and returns {:items #{x ...}}
  for the set's users, or the failed page's http/request! result."
  [db node]
  (loop [cursor nil, items #{}]
    (let [r (admin/request! db node
                            (str "/admin/users?limit=" page-size
                                 (when cursor (str "&cursor=" cursor)))
                            {})]
      (if (not= 200 (:status r))
        r
        (let [users  (get-in r [:body "items"])
              items' (into items
                           (keep #(some->> (get % "email") (re-matches item-pattern)
                                           second parse-long))
                           users)
              next   (get-in r [:body "next_cursor"])]
          (if (and next (seq users))
            (recur next items')
            {:items items'}))))))

(defrecord Client [db node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test] (admin/session! db test))

  (invoke! [_ _test op]
    (case (:f op)
      :add  (http/complete op :write
                           (admin/request! db node "/admin/users"
                                           {:method :post
                                            :json   {"email"        (email (:value op))
                                                     "display_name" (str "set " (:value op))}}))
      :read (let [r (read-items db node)]
              (if-let [items (:items r)]
                (assoc op :type :ok :value items :node node)
                (assoc (http/complete op :read r) :node node)))))

  (teardown! [_ _test])
  (close! [_ _test]))

(declare checker)

(defn workload
  "Adds unique users during the faults; after the heal, each client thread
  (one per node) reads the full set until a read succeeds, for at most
  120 s."
  [_opts db]
  {:client          (->Client db nil)
   :generator       (->> (range)
                         (map (fn [x] {:f :add :value x}))
                         (gen/stagger 1/20))
   :final-generator (gen/time-limit 120
                                    (gen/each-thread
                                      (gen/until-ok
                                        (gen/stagger 1 (gen/repeat {:f :read})))))
   :checker         (checker)})

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
