(ns jepsen.hearth.snapshot
  "The snapshot-install workload (R3, R4, xfail G2; design decision 7). Hearth
  has no API that forces a snapshot, so each round makes one: it cuts the
  target node (the last of the test) off from the other nodes, writes past
  openraft's snapshot point (a snapshot every 5,000 applied entries, then a
  purge that keeps 1,000), and heals; the target then catches up by snapshot
  install while it serves reads. A killed target would not do: it installs
  the snapshot at startup, before it serves HTTP. One writer thread writes
  increasing values to one user on the other nodes; one reader thread reads
  that user on the target in a loop; the rest pad the log.

  The suite runs it with cluster.read_lag_threshold_ms raised (see the
  catalog): with the default, the lag monitor happens to fence reads before
  the restore deletes a key, which hides G2.

  Checker: the target's reads never go backwards (R3) and never miss the
  user (R4). With G2 open, an install deletes every key before it writes the
  snapshot, and reads are not fenced meanwhile, so the test is xfail."
  (:require [clojure.java.io :as io]
            [clojure.string :as str]
            [jepsen [checker :as checker]
                    [client :as client]
                    [generator :as gen]
                    [nemesis :as n]
                    [store :as store]]
            [jepsen.hearth [admin :as admin]
                           [http :as http]
                           [register :as register]]))

(defn target
  "The node each round cuts off and heals: the last of the test."
  [test]
  (last (:nodes test)))

(def write-timeout-ms
  "How long a write waits on one node before it tries the next."
  3000)

(def pad-seconds
  "How long a round pads the log while the target is cut off. At the
  rates seen in Docker, enough for more than 10,000 entries."
  60)

(def read-seconds
  "How long a round reads on the target after the heal."
  30)

(defn installs-in-log
  "The number of \"snapshot installed\" lines in the target's hearth.log,
  as downloaded into the test's store directory."
  [test]
  (let [f (store/path test (target test) "hearth.log")]
    (if (.exists (io/file f))
      (with-open [r (io/reader f)]
        (count (filter #(str/includes? % "snapshot installed") (line-seq r))))
      0)))

(defn- backwards-reads
  "Reads that returned a lower value than a read on the same node that
  completed before they were invoked (R3). Overlapping reads may complete
  in either order."
  [history]
  (->> history
       (filter #(= :read (:f %)))
       (reduce (fn [{:keys [top floor out] :as acc} op]
                 (case (:type op)
                   :invoke (assoc-in acc [:floor (:process op)] top)
                   :ok     (let [node (:node op)
                                 v    (:value op)
                                 seen (get-in floor [(:process op) node])]
                             (if (integer? v)
                               (cond-> (update-in acc [:top node] (fnil max v) v)
                                 (and seen (< v seen))
                                 (update :out conj {:node node :read v :after seen}))
                               acc))
                   acc))
               {:top {} :floor {} :out []})
       :out))

(defn checker
  "Valid when (installs test) counts at least one snapshot install (a run
  with none proves nothing), no :ok read on a node returned a value lower
  than a read there that completed before it began (R3), and no :ok read found the user missing
  (R4). Each read carries the :node it ran on."
  [installs]
  (reify checker/Checker
    (check [_ test history _opts]
      (let [reads     (filter #(and (= :read (:f %)) (= :ok (:type %))) history)
            n         (installs test)
            backwards (backwards-reads history)
            missing   (count (filter #(= :missing (:value %)) reads))]
        (cond
          (zero? n)
          {:valid? false
           :error  "no snapshot install was logged on the target; the run proves nothing"}

          (or (seq backwards) (pos? missing))
          {:valid?    false
           :installs  n
           :reads     (count reads)
           :backwards (vec (take 20 backwards))
           :missing   missing
           :error     "a read on the target went backwards or missed the user"}

          :else
          {:valid? true :installs n :reads (count reads)})))))

(defn- others
  "The nodes other than the target, from this client's own when it is one."
  [test node]
  (let [os (remove #{(target test)} (:nodes test))]
    (if (some #{node} os) (cons node (remove #{node} os)) os)))

(defn- patch!
  "PATCHes user `id`'s display_name on each of `nodes` in turn until one
  answers 200. Returns the last result, with :written-on."
  [db nodes id display-name]
  (loop [[at & more] nodes]
    (let [r (admin/request! db at (str "/admin/users/" id)
                            {:method  :patch
                             :timeout write-timeout-ms
                             :json    {"display_name" display-name}})]
      (if (and (not= 200 (:status r)) (seq more))
        (recur more)
        (assoc r :written-on at)))))

(def ^:private email
  "The user the writer writes and the reader reads."
  "r3@jepsen.test")

(def ^:private page-size
  "One page of the user list holds every user of the run: the realm admin,
  the R3 user and the pad user."
  100)

(defn- create-user!
  [db node email]
  (let [r (admin/request! db node "/admin/users"
                          {:method :post
                           :json   {"email" email "display_name" "init"}})]
    (or (get-in r [:body "id"])
        (throw (ex-info (str "creating " email " failed")
                        {:status (:status r) :body (:body r)})))))

(defrecord Client [db state node]
  client/Client
  (open! [this _test node] (assoc this :node node))

  (setup! [_ test]
    (admin/session! db test)
    (locking state
      (when-not (:user @state)
        (reset! state {:user (create-user! db (first (:nodes test)) email)
                       :pad  (create-user! db (first (:nodes test)) "pad@jepsen.test")}))))

  (invoke! [_ test op]
    (let [{:keys [user pad]} @state]
      (case (:f op)
        :write (let [r (patch! db (others test node) user (register/render-value (:value op)))]
                 (assoc (http/complete op :write r) :written-on (:written-on r)))
        :pad   (http/complete op :write
                              (patch! db (others test node) pad (str "p" (:value op))))
        ; The user list scans storage. GET /admin/users/<id> may answer from
        ; the in-memory hot tier, which an install does not wipe.
        :read  (let [at (target test)
                     r  (admin/request! db at (str "/admin/users?limit=" page-size) {})]
                 (case (:status r)
                   200 (let [u (some #(when (= email (get % "email")) %)
                                     (get-in r [:body "items"]))]
                         (assoc op :type :ok :node at
                                :value (if u
                                         (register/parse-value (get u "display_name"))
                                         :missing)))
                   ; The admin's session (401), or the grant or first-party
                   ; client that admits its token (403), is gone. All existed
                   ; before the round and nothing deletes them; a node that
                   ; cannot read answers 503.
                   (401 403) (assoc op :type :ok :node at :value :missing
                                    :status (:status r))
                   (assoc (http/complete op :read r) :node at))))))

  (teardown! [_ _test])
  (close! [_ _test]))

(defn- cut-off-target
  "Starts a partition that cuts the target off from every other node."
  []
  (gen/nemesis
    (gen/once (fn [test _ctx]
                (let [t (target test)]
                  {:type  :info
                   :f     :start-partition
                   :value (n/complete-grudge [[t] (remove #{t} (:nodes test))])})))))

(defn- round
  "One round: cut the target off, pad the log, heal, then read on the
  target while it installs the snapshot. The reader reads throughout.
  `write` is the writer's generator; it numbers the writes across rounds,
  so the values keep increasing."
  [write]
  (let [writer (fn [secs] (gen/time-limit secs (gen/stagger 1/10 write)))
        ; One thread reads about every millisecond: below the admin rate
        ; limit (security.rate_limiting.admin_per_minute, 100000 in
        ; gen-configs.sh), which back-to-back reads exceed.
        reader (fn [secs] (gen/time-limit secs (gen/stagger 1/1000 (gen/repeat {:f :read}))))]
    (gen/phases
      (cut-off-target)
      (gen/clients (gen/reserve 1 (writer pad-seconds)
                                1 (reader pad-seconds)
                                (gen/time-limit pad-seconds
                                                (map (fn [n] {:f :pad :value n}) (range)))))
      (gen/nemesis {:type :info :f :stop-partition :value nil})
      (gen/clients (gen/reserve 1 (writer read-seconds)
                                1 (reader read-seconds)
                                ; The other threads idle until the round ends.
                                (gen/sleep read-seconds))))))

(defn workload
  "Rounds of `round`. The workload times its own faults
  (:combined-generator)."
  [_opts db]
  (let [n     (atom 0)
        write (fn [] {:f :write :value (swap! n inc)})]
    {:client             (->Client db (atom {}) nil)
     :combined-generator (repeatedly #(round write))
     :checker            (checker installs-in-log)}))
