(ns jepsen.hearth.snapshot-test
  "The snapshot-install checker (R3, R4) on hand-written histories, with
  planted violations (spec: \"The checkers are proven before they are
  trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.snapshot :as snapshot]))

(defn- read
  "A read on `node` that returned `v` (:missing for a 404)."
  [node v]
  [{:process 4 :type :invoke :f :read :value nil :node node}
   {:process 4 :type :ok :f :read :value v :node node}])

(defn- check
  "Checks `ops` with `installs` snapshot installs logged on the target."
  [installs & ops]
  (checker/check (snapshot/checker (constantly installs)) {:nodes ["n1" "n5"]}
                 (h/history (vec (apply concat ops))) {}))

(deftest reads-that-only-move-forward-are-valid
  (let [r (check 1 (read "n5" nil) (read "n5" 3) (read "n5" 3) (read "n5" 9))]
    (is (true? (:valid? r)) (pr-str r))
    (is (= 4 (:reads r)) (pr-str r))))

(deftest a-read-that-goes-backwards-is-invalid
  (testing "planted violation (R3): n5 reads 9, then 4"
    (let [r (check 1 (read "n5" 3) (read "n5" 9) (read "n5" 4))]
      (is (false? (:valid? r)))
      (is (= [{:node "n5" :read 4 :after 9}] (:backwards r)) (pr-str r)))))

(deftest overlapping-reads-may-complete-in-either-order
  (testing "R3 binds a read only to the reads that completed before it began"
    (let [r (check 1
                   [{:process 1 :type :invoke :f :read :value nil :node "n5"}
                    {:process 2 :type :invoke :f :read :value nil :node "n5"}
                    {:process 2 :type :ok :f :read :value 9 :node "n5"}
                    {:process 1 :type :ok :f :read :value 4 :node "n5"}]
                   (read "n5" 9))]
      (is (true? (:valid? r)) (pr-str r)))))

(deftest a-read-of-missing-data-is-invalid
  (testing "planted violation (R4): the user is gone mid-install"
    (let [r (check 1 (read "n5" 3) (read "n5" :missing) (read "n5" 5))]
      (is (false? (:valid? r)))
      (is (= 1 (:missing r)) (pr-str r)))))

(deftest a-run-with-no-snapshot-install-proves-nothing
  (let [r (check 0 (read "n5" 3) (read "n5" 4))]
    (is (false? (:valid? r)))
    (is (re-find #"no snapshot install" (:error r)) (pr-str r))))
