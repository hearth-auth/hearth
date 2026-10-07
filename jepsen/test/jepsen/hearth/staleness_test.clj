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
