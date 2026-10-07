(ns jepsen.hearth.set-test
  "The set workload's checker (W1, W2) on hand-written histories, each with
  a planted violation (spec: \"The checkers are proven before they are
  trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.set :as hset]))

(defn- add
  "An add of `x` by `process` that completes with `type`."
  [process x type]
  [{:process process :type :invoke :f :add :value x}
   {:process process :type type :f :add :value x}])

(defn- final-read
  "A final read on `node` (process `process`) that returns `xs`."
  [process node xs]
  [{:process process :type :invoke :f :read :value nil :node node}
   {:process process :type :ok :f :read :value (set xs) :node node}])

(defn- history
  [& op-pairs]
  (h/history (vec (apply concat op-pairs))))

(def test-map {:nodes ["n1" "n2" "n3"]})

(defn- check [hist]
  (checker/check (hset/checker) test-map hist {}))

(deftest every-acknowledged-add-on-every-node-is-valid
  (let [r (check (history (add 0 1 :ok) (add 1 2 :ok)
                          ; An unknown add may or may not be there.
                          (add 2 3 :info)
                          ; A failed add may not be there.
                          (add 3 4 :fail)
                          (final-read 0 "n1" [1 2 3])
                          (final-read 1 "n2" [1 2])
                          (final-read 2 "n3" [1 2 3])))]
    (is (true? (:valid? r)) (pr-str r))))

(deftest an-acknowledged-add-missing-from-one-node-is-invalid
  (testing "planted violation: an :ok add missing from a final read"
    (let [r (check (history (add 0 1 :ok) (add 1 2 :ok)
                            (final-read 0 "n1" [1 2])
                            (final-read 1 "n2" [1])
                            (final-read 2 "n3" [1 2])))]
      (is (false? (:valid? r)))
      (is (= {"n2" #{2}} (get-in r [:every-node :missing])) (pr-str r))
      (testing "set-full alone misses it: n3's later read shows the add"
        (is (true? (get-in r [:set-full :valid?])) (pr-str (:set-full r)))))))

(deftest a-node-without-a-final-read-is-invalid
  (testing "a node that never answered its final read proves nothing"
    (let [r (check (history (add 0 1 :ok)
                            (final-read 0 "n1" [1])
                            (final-read 1 "n2" [1])))]
      (is (false? (:valid? r)))
      (is (= ["n3"] (get-in r [:every-node :unread])) (pr-str r)))))

(deftest a-failed-add-that-appears-is-invalid
  (testing "a :fail add must not take effect"
    (let [r (check (history (add 0 1 :ok) (add 1 2 :fail)
                            (final-read 0 "n1" [1 2])
                            (final-read 1 "n2" [1 2])
                            (final-read 2 "n3" [1 2])))]
      (is (false? (:valid? r)))
      (is (= #{2} (get-in r [:every-node :unexpected])) (pr-str r)))))
