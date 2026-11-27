(ns jepsen.hearth.staleness
  "The bounded-staleness workload (R2; design decision 7): one
  writer thread writes increasing values to one user's display_name; every
  other client thread reads it on its own node, during partitions that cut
  off one side or the leader.

  Checker: a read invoked more than `read-lag-ms` after a write was
  acknowledged shows that write or a later one. A node that cannot keep up
  must answer unavailable, never serve the older value (G1, closed)."
  (:require [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]]
            [jepsen.history :as h]
            [jepsen.hearth [admin :as admin]
                           [http :as http]
                           [register :as register]]))

(def read-lag-ms
  "cluster.read_lag_threshold_ms: gen-configs.sh leaves it at the server's
  default, 500."
  500)

(def ^:private ns-per-ms 1000000)

(def write-timeout-ms
  "How long a write waits on one node before it tries the next."
  3000)

(defn- floors
  "time -> [value completed-at] of the highest value acknowledged by then,
  from the :ok writes, as a sorted map."
  [history]
  (->> history
       (filter #(and (= :write (:f %)) (= :ok (:type %))))
       (sort-by :time)
       (reduce (fn [[m best] op]
                 (let [best (if (or (nil? best) (< (first best) (:value op)))
                              [(:value op) (:time op)]
                              best)]
                   [(assoc m (:time op) best) best]))
               [(sorted-map) nil])
       first))

(defn- indeterminate-values
  "The values of the :info writes: their outcome is unknown, so each may
  land at any time after its invocation, also after a later acknowledged
  write (a write that timed out on a cut-off leader is forwarded to the new
  leader once the partition heals)."
  [history]
  (into #{}
        (comp (filter #(and (= :write (:f %)) (= :info (:type %))))
              (map :value))
        history))

(defn checker
  "Valid when no :ok read invoked more than the test map's :read-lag-ms
  (default `read-lag-ms`) after a write was acknowledged returned a lower
  value (other than one an indeterminate write wrote), and at least one read had such a write to check against (a run with
  none proves nothing). Each read carries the :node it ran on."
  []
  (reify checker/Checker
    (check [_ test history _opts]
      (let [lag     (* ns-per-ms (:read-lag-ms test read-lag-ms))
            floor   (floors history)
            late-ok (indeterminate-values history)
            checked (for [op    (filter #(and (= :read (:f %)) (= :ok (:type %))) history)
                          :let  [start (:time (h/invocation history op))
                                 [_ [v at]] (first (rsubseq floor <= (- start lag)))]
                          :when v]
                      {:node              (:node op)
                       :read              (:value op)
                       :expected-at-least v
                       :after-ms          (quot (- start at) ns-per-ms)})
            stale   (vec (filter #(and (< (or (:read %) -1) (:expected-at-least %))
                                       (not (late-ok (:read %))))
                                 checked))]
        (cond
          (empty? checked)
          {:valid?      false
           :read-lag-ms (quot lag ns-per-ms)
           :error       "no read followed an acknowledged write by the threshold; the run proves nothing"}

          (seq stale)
          {:valid?      false
           :read-lag-ms (quot lag ns-per-ms)
           :checked     (count checked)
           :stale       stale
           :error       "a read missed a write acknowledged more than the threshold before it"}

          :else
          {:valid? true :read-lag-ms (quot lag ns-per-ms) :checked (count checked)})))))

(defn write-outcome
  "The completion of a write from its attempts' HTTP results, in order. A
  write any attempt of which has an unknown outcome is :info unless a later
  attempt succeeded: the earlier attempt may still land, after the refusals
  that followed it."
  [results]
  (let [last-result (peek (vec results))
        completion  (http/outcome :write last-result)]
    (if (and (not= :ok (:type completion))
             (some #(= :info (:type (http/outcome :write %))) results))
      (assoc completion :type :info)
      completion)))

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test]
    (admin/session! db test)
    (locking state
      (when-not (:user @state)
        (let [r (admin/request! db (first (:nodes test)) "/admin/users"
                                {:method :post
                                 :json   {"email" "r2@jepsen.test" "display_name" "init"}})]
          (swap! state assoc :user
                 (or (get-in r [:body "id"])
                     (throw (ex-info "creating the R2 user failed"
                                     {:status (:status r) :body (:body r)}))))))))

  (invoke! [_ test op]
    (let [path (str "/admin/users/" (:user @state))]
      (case (:f op)
        ; Tries each node in turn, from this client's own: the writes must
        ; reach the side of the partition that can commit them.
        :write (loop [[at & more] (cons node (remove #{node} (:nodes test)))
                      results     []]
                 (let [r       (admin/request! db at path
                                               {:method  :patch
                                                :timeout write-timeout-ms
                                                :json    {"display_name"
                                                          (register/render-value (:value op))}})
                       results (conj results r)]
                   (if (and (not= 200 (:status r)) (seq more))
                     (recur more results)
                     (assoc (merge op (write-outcome results)) :written-on at))))
        :read  (let [r (admin/request! db node path {})]
                 (if (= 200 (:status r))
                   (assoc op :type :ok :node node
                          :value (register/parse-value (get-in r [:body "display_name"])))
                   (assoc (http/complete op :read r) :node node))))))

  (teardown! [_ _test])
  (close! [_ _test]))

(defn workload
  "One writer thread writes 1, 2, 3, ... and reads on its own node between
  writes; the other client threads read on their own nodes."
  [_opts db]
  {:client    (->Client db (atom {}) nil)
   :generator (gen/reserve
                1 (->> (range 1 Long/MAX_VALUE)
                       (mapcat (fn [n] [{:f :write :value n} {:f :read}]))
                       (gen/stagger 1/10))
                (gen/stagger 1/20 (gen/repeat {:f :read})))
   :checker   (checker)})
