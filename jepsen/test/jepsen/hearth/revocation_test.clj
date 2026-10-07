(ns jepsen.hearth.revocation-test
  "The revocation checker (V1) on hand-written histories, with a planted
  violation (spec: \"The checkers are proven before they are trusted\")."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.history :as h]
            [jepsen.hearth.revocation :as revocation]))

(def ms 1000000)

(defn- revoke
  "Session `s` revoked by `process`, invoked at `t0` ms, completing at `t1` ms."
  [process s t0 t1]
  [{:process process :type :invoke :f :revoke :value s :time (* t0 ms)}
   {:process process :type :ok :f :revoke :value s :time (* t1 ms)}])

(defn- validate
  "Session `s` validated on `node` by `process`, invoked at `t0` ms; `active?`
  is what the node answered."
  [process node s t0 active?]
  [{:process process :type :invoke :f :validate :value s :node node :time (* t0 ms)}
   {:process process :type :ok :f :validate :value s :node node :active? active?
    :time (* (inc t0) ms)}])

;; No injected delay: the bound is 400 ms + 2 x 0 + 1 s slack = 1400 ms.
(def test-map {:v1-delay-ms 0})

(defn- check [& pairs]
  (checker/check (revocation/checker) test-map
                 (h/history (vec (sort-by :time (apply concat pairs))))
                 {}))

(deftest the-bound-follows-open-question-5
  (is (= 1400 (revocation/bound-ms 0)))
  (is (= 1800 (revocation/bound-ms 200))))

(deftest a-probe-that-never-saw-a-live-session-proves-nothing
  (testing "every validation rejects, even before the revocation"
    (let [r (check (validate 1 "n2" :s1 0 false)
                   (revoke 0 :s1 10 20)
                   (validate 1 "n2" :s1 2000 false))]
      (is (false? (:valid? r)))
      (is (re-find #"never saw a live session" (:error r)) (pr-str r)))))

(deftest rejection-within-the-bound-is-valid
  (let [r (check (validate 3 "n1" :s1 -10 true)
                 (revoke 0 :s1 0 10)
                 ; Before the bound a node may still accept.
                 (validate 1 "n2" :s1 500 true)
                 (validate 2 "n3" :s1 1500 false)
                 (validate 1 "n2" :s1 2000 false))]
    (is (true? (:valid? r)) (pr-str r))
    (is (= 1400 (:bound-ms r)))))

(deftest acceptance-after-the-bound-is-invalid
  (testing "planted violation: n3 accepts the session 2 s after the revoke"
    (let [r (check (validate 3 "n1" :s1 -10 true)
                   (revoke 0 :s1 0 10)
                   (validate 1 "n2" :s1 1500 false)
                   (validate 2 "n3" :s1 2010 true))]
      (is (false? (:valid? r)))
      (is (= [{:session :s1 :node "n3" :after-ms 2000}] (:late r)) (pr-str r)))))

(deftest a-run-with-no-revocation-proves-nothing
  (let [r (check (validate 1 "n2" :s1 0 true))]
    (is (false? (:valid? r)))
    (is (re-find #"no revocation" (:error r)) (pr-str r))))
