(ns jepsen.hearth.staleness-test
  "The bounded-staleness checker (R2) on hand-written histories, with a
  planted violation (spec: \"The checkers are proven before they are
  trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.staleness :as staleness]))

(def ms 1000000)

(defn- write
  "Write of `v` invoked at `t0` ms, completing at `t1` ms with `type`."
  [v t0 t1 type]
  [{:process 0 :type :invoke :f :write :value v :time (* t0 ms)}
   {:process 0 :type type :f :write :value v :time (* t1 ms)}])

(defn- read
  "Read on `node` by `process` invoked at `t0` ms, returning `v`."
  [process node t0 v]
  [{:process process :type :invoke :f :read :value nil :node node :time (* t0 ms)}
   {:process process :type :ok :f :read :value v :node node :time (* (inc t0) ms)}])

(def test-map {:read-lag-ms 500})

(defn- check [& pairs]
  (checker/check (staleness/checker) test-map
                 (h/history (vec (sort-by :time (apply concat pairs)))) {}))

(deftest reads-within-the-threshold-may-lag
  (let [r (check (write 1 0 10 :ok)
                 (read 1 "n2" 100 nil)      ; 90 ms after: may still miss it
                 (read 1 "n2" 600 1)        ; 590 ms after: must show it
                 (write 2 700 710 :info)    ; unknown: sets no floor
                 (read 2 "n3" 1500 1))]
    (is (true? (:valid? r)) (pr-str r))
    (is (= 2 (:checked r)) (pr-str r))))

(deftest a-stale-read-after-the-threshold-is-invalid
  (testing "planted violation: n3 reads 1 a second after 2 was acknowledged"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 30 :ok)
                   (read 1 "n2" 600 2)
                   (read 2 "n3" 1030 1))]
      (is (false? (:valid? r)))
      (is (= [{:node "n3" :read 1 :expected-at-least 2 :after-ms 1000}] (:stale r))
          (pr-str r)))))

(deftest a-run-that-checked-no-read-proves-nothing
  (let [r (check (write 1 0 10 :ok) (read 1 "n2" 100 nil))]
    (is (false? (:valid? r)))
    (is (re-find #"no read" (:error r)) (pr-str r))))

(deftest a-read-of-an-indeterminate-write-may-follow-a-later-one
  (testing "a write whose outcome is unknown can land after a later acknowledged write"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 3020 :info)     ; timed out on its node
                   (write 3 3030 3040 :ok)
                   (read 1 "n2" 3600 3)
                   (read 1 "n2" 4000 2)        ; the late write 2 landed, over 3
                   (read 2 "n3" 4100 2))]
      (is (true? (:valid? r)) (pr-str r))))
  (testing "a value no write left indeterminate is still stale"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 3020 :info)
                   (write 3 3030 3040 :ok)
                   (read 1 "n2" 4000 1))]
      (is (false? (:valid? r)) (pr-str r)))))

(deftest a-node-frozen-on-an-indeterminate-value-is-stale
  (testing "planted violation: n3 keeps showing 2, which landed before 3 was written"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 3020 :info)     ; landed, but its answer timed out
                   (read 1 "n2" 100 2)         ; 2 is in the register before 3 is written
                   (write 3 3030 3040 :ok)
                   (read 1 "n2" 3600 3)
                   (read 2 "n3" 4000 2)        ; 960 ms after 3: stale
                   (read 2 "n3" 9000 2))]
      (is (false? (:valid? r)) (pr-str r))
      (is (= [{:node "n3" :read 2 :expected-at-least 3 :after-ms 960}
              {:node "n3" :read 2 :expected-at-least 3 :after-ms 5960}]
             (:stale r))
          (pr-str r))))
  (testing "planted violation: a node showed 2 and then 3, so 3 overwrote 2"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 3020 :info)
                   (write 3 3030 3040 :ok)
                   (read 1 "n2" 3035 2)        ; ends after 3 was invoked
                   (read 1 "n2" 3100 3)        ; same node, later: 3 came after 2
                   (read 2 "n3" 5000 2))]
      (is (false? (:valid? r)) (pr-str r))
      (is (= [{:node "n3" :read 2 :expected-at-least 3 :after-ms 1960}] (:stale r))
          (pr-str r))))
  (testing "a late write overwrites the acknowledged ones, and the next write overwrites it"
    (let [r (check (write 1 0 10 :ok)
                   (write 2 20 3020 :info)     ; held by a cut-off leader
                   (write 3 3030 3040 :ok)
                   (read 1 "n2" 3600 3)
                   (read 1 "n2" 4000 2)        ; 2 committed after the heal, over 3
                   (read 2 "n3" 4100 2)
                   (write 4 5000 5010 :ok)
                   (read 1 "n2" 5600 4)
                   (read 2 "n3" 6000 2))]      ; 4 overwrote 2: stale
      (is (false? (:valid? r)) (pr-str r))
      (is (= [{:node "n3" :read 2 :expected-at-least 4 :after-ms 990}] (:stale r))
          (pr-str r))))
  (testing "a write with two unknown attempts may land twice: once before 3, once after"
    (let [r (check (write 1 0 10 :ok)
                   [{:process 0 :type :invoke :f :write :value 2 :time (* 20 ms)}
                    {:process 0 :type :info :f :write :value 2 :unknown-attempts 2
                     :time (* 6020 ms)}]
                   (read 1 "n2" 100 2)
                   (write 3 6030 6040 :ok)
                   (read 1 "n2" 6600 3)
                   (read 2 "n3" 8000 2))]  ; the second attempt landed after 3
      (is (true? (:valid? r)) (pr-str r)))))

(deftest a-write-with-one-indeterminate-attempt-is-indeterminate
  (let [timeout     {:error :timeout}
        unavailable {:status 503 :body {"error_code" "HEARTH_CLUSTER_UNAVAILABLE"}}
        ok          {:status 200 :body {}}]
    (testing "a timeout, then refusals elsewhere: the first attempt may still land"
      (is (= {:type :info :unknown-attempts 1}
             (select-keys (staleness/write-outcome [timeout unavailable unavailable])
                          [:type :unknown-attempts]))))
    (testing "every attempt that timed out may land"
      (is (= 2 (:unknown-attempts (staleness/write-outcome [timeout timeout unavailable])))))
    (is (= :ok (:type (staleness/write-outcome [timeout ok]))))
    (is (= :fail (:type (staleness/write-outcome [unavailable unavailable]))))))
