(ns jepsen.hearth.register
  "The register workload (W1, W2, W3; design decision 7): one mutable user
  field per key. Clients write during the faults; after the heal every node
  reads every key once.

  Checkers: Knossos over the writes plus the final reads, per key (a write
  that ends :info may or may not have happened, W3), and `agree-checker`:
  every node read every key, and all nodes read the same value. Knossos
  alone cannot see a disagreement that an unknown write could explain."
  (:require [clojure.tools.logging :refer [info]]
            [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]
                    [independent :as independent]]
            [jepsen.hearth [admin :as admin]
                           [deferred :as deferred]
                           [http :as http]]
            [knossos.model :as model]))

(defn parse-value
  "The register value of a display_name: n for \"v<n>\", nil otherwise
  (\"init\", before any write)."
  [display-name]
  (some->> display-name str (re-matches #"v(\d+)") second parse-long))

(defn render-value
  "The display_name that holds value `v`. The prefix keeps the REST layer
  from turning it into a JSON number."
  [v]
  (str "v" v))

(def writes-per-key
  "Writes on one key before the clients move to the next. Bounds the :info
  writes Knossos keeps open per key."
  60)

(def write-rate
  "Writes per second, across all clients."
  20)

(defn key-count
  "Keys to create for a run of `time-limit` seconds, with half again spare."
  [time-limit]
  (long (Math/ceil (* 1.5 (/ (* time-limit write-rate) writes-per-key)))))

(defn- create-users!
  "Creates one user per key on `node`; returns their IDs, indexed by key."
  [db node n]
  (mapv (fn [k]
          (let [r (admin/request! db node "/admin/users"
                                  {:method :post
                                   :json   {"email"        (str "reg-" k "@jepsen.test")
                                            "display_name" "init"}})]
            (or (get-in r [:body "id"])
                (throw (ex-info (str "creating the user of key " k " failed")
                                {:status (:status r) :body (:body r)})))))
        (range n)))

(def final-read-attempts
  "Tries per final read. The reads follow the heal, so a failure is
  transient; one that persists leaves the node unread, which is invalid."
  10)

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test]
    (admin/session! db test)
    (locking state
      (when-not (:users @state)
        (let [n (key-count (:time-limit test))]
          (swap! state assoc :users (create-users! db (first (:nodes test)) n))
          (info "created" n "register users")))))

  (invoke! [_ _test op]
    (let [[k v] (:value op)
          path  (str "/admin/users/" (get-in @state [:users k]))]
      (case (:f op)
        :write (do (swap! state update :touched (fnil conj (sorted-set)) k)
                   (http/complete op :write
                                  (admin/request! db node path
                                                  {:method :patch
                                                   :json   {"display_name" (render-value v)}})))
        :read  (loop [attempt 1]
                 (let [r (admin/request! db node path {})]
                   (cond
                     (= 200 (:status r))
                     (assoc op :type :ok :node node
                            :value (independent/tuple
                                     k (parse-value (get-in r [:body "display_name"]))))

                     (< attempt final-read-attempts)
                     (do (Thread/sleep 1000) (recur (inc attempt)))

                     :else
                     (assoc (http/complete op :read r) :node node)))))))

  (teardown! [_ _test])
  (close! [_ _test]))

(declare checker)

(defn workload
  "Writes small values to one user's display_name per key, all clients on
  one key at a time; after the heal, every client thread (one per node)
  reads every written key once."
  [opts db]
  (let [state (atom {})
        n     (count (:nodes opts))]
    {:client          (->Client db state nil)
     :generator       (independent/concurrent-generator
                        n
                        (range (key-count (:time-limit opts)))
                        (fn [_k]
                          (->> (fn [] {:f :write :value (rand-int 5)})
                               (gen/stagger (/ 1 write-rate))
                               (gen/limit writes-per-key))))
     ; Built after the run, when the touched keys are known.
     :final-generator (gen/each-thread
                        (deferred/deferred
                          (fn []
                            (for [k (:touched @state)]
                              {:f :read :value (independent/tuple k nil)}))))
     :checker         (checker)}))

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
                                   ; contains?, not the map as a predicate:
                                   ; nil is a value a node read.
                                   (let [read    (get finals k {})
                                         missing (vec (remove #(contains? read %)
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
