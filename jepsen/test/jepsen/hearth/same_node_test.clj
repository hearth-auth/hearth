(ns jepsen.hearth.same-node-test
  "The same-node read checker (R1) on hand-written histories, with a planted
  violation (spec: \"The checkers are proven before they are trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.same-node :as same-node]))

(defn- write-read
  "One write-then-read of `v` by `process` on `node`, completing with `type`;
  an :ok op carries the value its read returned."
  ([process node v type] (write-read process node v type v))
  ([process node v type read]
   [{:process process :type :invoke :f :write-read :value v :node node}
    (cond-> {:process process :type type :f :write-read :value v :node node}
      (= :ok type) (assoc :read read))]))

(defn- check [& pairs]
  (checker/check (same-node/checker) {} (h/history (vec (apply concat pairs))) {}))

(deftest reads-that-show-the-write-are-valid
  (let [r (check (write-read 0 "n1" 1 :ok) (write-read 1 "n2" 2 :ok)
                 ; A failed or unknown write has no read to check.
                 (write-read 0 "n1" 3 :fail) (write-read 1 "n2" 4 :info))]
    (is (true? (:valid? r)) (pr-str r))
    (is (= 2 (:checked r)))))

(deftest a-read-that-misses-the-write-on-its-node-is-invalid
  (testing "planted violation: n2 acknowledged 5, then read 2"
    (let [r (check (write-read 0 "n1" 1 :ok)
                   (write-read 1 "n2" 2 :ok)
                   (write-read 1 "n2" 5 :ok 2))]
      (is (false? (:valid? r)))
      (is (= [{:node "n2" :process 1 :wrote 5 :read 2}] (:stale r)) (pr-str r)))))

(deftest a-run-with-nothing-checked-proves-nothing
  (let [r (check (write-read 0 "n1" 1 :fail))]
    (is (false? (:valid? r)))
    (is (re-find #"no write" (:error r)) (pr-str r))))
