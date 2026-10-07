(ns jepsen.hearth.register-test
  "The register workload's checker (W1, W2, W3) on hand-written histories,
  each with a planted violation (spec: \"The checkers are proven before they
  are trusted\")."
  (:require [clojure.test :refer [deftest is testing use-fixtures]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.independent :as independent]
            [jepsen.store :as store]
            [jepsen.hearth.register :as register]))

(def ^:private tmp-store
  (str (System/getProperty "java.io.tmpdir") "/hearth-register-test-store"))

;; independent/checker writes per-key results into the test's store.
(use-fixtures :each
  (fn [t] (with-redefs [store/base-dir tmp-store] (t))))

(def test-map {:name       "register-unit"
               :start-time (java.time.ZonedDateTime/now)
               :nodes      ["n1" "n2" "n3"]})

(defn- write
  "A write of `v` to key `k` by `process`, completing with `type`."
  [process k v type]
  [{:process process :type :invoke :f :write :value (independent/tuple k v)}
   {:process process :type type :f :write :value (independent/tuple k v)}])

(defn- final-read
  "A final read of key `k` on `node` that returns `v`."
  [process node k v]
  [{:process process :type :invoke :f :read :value (independent/tuple k nil) :node node}
   {:process process :type :ok :f :read :value (independent/tuple k v) :node node}])

(defn- reads-on-every-node
  "Final reads of key `k` on n1, n2 and n3 returning vs."
  [k vs]
  (map-indexed (fn [i [node v]] (final-read (+ 10 i) node k v))
               (map vector (:nodes test-map) vs)))

(defn- flatten-pairs
  "op-pairs mixes single pairs and seqs of pairs."
  [op-pairs]
  (mapcat (fn [x] (if (map? (first x)) [x] x)) op-pairs))

(defn- check [& op-pairs]
  (let [hist (h/history (vec (apply concat (flatten-pairs op-pairs))))]
    (checker/check (register/checker) test-map hist {})))

(deftest the-last-acknowledged-value-on-every-node-is-valid
  (let [r (check (write 0 :a 1 :ok)
                 (write 1 :a 2 :info)
                 (write 2 :b 7 :ok)
                 (reads-on-every-node :a [2 2 2])
                 (reads-on-every-node :b [7 7 7]))]
    (is (true? (:valid? r)) (pr-str r))))

(deftest a-final-value-no-linearization-allows-is-invalid
  (testing "planted violation: 2 overwrote 1, yet every node reads 1"
    (let [r (check (write 0 :a 1 :ok)
                   (write 1 :a 2 :ok)
                   (reads-on-every-node :a [1 1 1]))]
      (is (false? (:valid? r)))
      (is (false? (get-in r [:linear :valid?])) (pr-str r))
      (is (true? (get-in r [:agree :valid?])) (pr-str r)))))

(deftest a-failed-write-visible-at-the-end-is-invalid
  (testing "planted violation: a :fail write must not take effect"
    (let [r (check (write 0 :a 1 :ok)
                   (write 1 :a 2 :fail)
                   (reads-on-every-node :a [2 2 2]))]
      (is (false? (:valid? r)))
      (is (false? (get-in r [:linear :valid?])) (pr-str r)))))

(deftest nodes-that-disagree-are-invalid
  (testing "planted violation: Knossos alone accepts this, since the unknown
            write can linearize between n1's read and n2's"
    (let [r (check (write 0 :a 1 :ok)
                   (write 1 :a 2 :info)
                   (reads-on-every-node :a [1 2 2]))]
      (is (true? (get-in r [:linear :valid?])) (pr-str r))
      (is (false? (:valid? r)))
      (is (= {:a {"n1" 1 "n2" 2 "n3" 2}} (get-in r [:agree :disagree])) (pr-str r)))))

(deftest a-key-whose-writes-all-failed-reads-nil-everywhere
  (testing "nil is a value read, not a missing read"
    (let [r (check (write 0 :a 1 :fail)
                   (reads-on-every-node :a [nil nil nil]))]
      (is (true? (:valid? r)) (pr-str r)))))

(deftest a-node-without-a-final-read-is-invalid
  (let [r (check (write 0 :a 1 :ok)
                 (final-read 10 "n1" :a 1)
                 (final-read 11 "n2" :a 1))]
    (is (false? (:valid? r)))
    (is (= {:a ["n3"]} (get-in r [:agree :unread])) (pr-str r))))

(deftest a-register-value-is-the-display-name-without-its-prefix
  ; hearth's REST layer turns an all-digit string into a JSON number, so the
  ; value carries a prefix; "init" is the value before any write.
  (is (= 3 (register/parse-value "v3")))
  (is (nil? (register/parse-value "init")))
  (is (nil? (register/parse-value nil)))
  (is (= "v3" (register/render-value 3))))
