(ns jepsen.hearth.converge-test
  "The heal-and-converge phase (spec: \"Final reads follow a heal\"), with
  stubbed status answers."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.checker :as checker]
            [jepsen.hearth.converge :as converge]))

(def nodes ["n1" "n2" "n3" "n4" "n5"])

(def fast {:timeout-ms 300 :interval-ms 10})

(defn- stuck
  "n1-n4 at index 42; `node` stays at 30."
  [node]
  (fn [n] (if (= n node) 30 42)))

(deftest equal-indices-converge
  (let [r (converge/await-convergence (constantly 42) nodes fast)]
    (is (:converged? r))
    (is (= 42 (:index r)))))

(deftest a-node-that-catches-up-converges
  (let [polls (atom 0)
        fetch (fn [n] (if (= n "n5")
                        (if (< (swap! polls inc) 3) 30 42)
                        42))
        r     (converge/await-convergence fetch nodes fast)]
    (is (:converged? r))
    (is (= 42 (:index r)))))

(deftest a-node-that-stays-behind-is-named
  (let [r (converge/await-convergence (stuck "n5") nodes fast)]
    (is (false? (:converged? r)))
    (is (= ["n5"] (:lagging r)))
    (is (= 30 (get-in r [:indices "n5"])))))

(deftest an-unreachable-node-does-not-converge
  (let [r (converge/await-convergence (fn [n] (when-not (= n "n2") 42))
                                      nodes fast)]
    (is (false? (:converged? r)))
    (is (= ["n2"] (:lagging r)))))

;; Jepsen records a nemesis invocation as :info with a nil value, like its
;; completion; only the completion carries the result.
(deftest the-checker-fails-a-test-whose-nodes-did-not-converge
  (let [result  (converge/await-convergence (stuck "n5") nodes fast)
        history [{:index 0 :type :info :process :nemesis :f :converge :value nil}
                 {:index 1 :type :info :process :nemesis :f :converge
                  :value result}]
        verdict (checker/check (converge/checker) {} history {})]
    (is (false? (:valid? verdict)))
    (is (= ["n5"] (:lagging verdict)))
    (is (re-find #"n5" (:error verdict)))))

(deftest the-checker-passes-a-converged-test
  (let [history [{:index 0 :type :info :process :nemesis :f :converge :value nil}
                 {:index 1 :type :info :process :nemesis :f :converge
                  :value {:converged? true :index 42}}]]
    (is (true? (:valid? (checker/check (converge/checker) {} history {}))))))

(deftest the-checker-fails-a-test-that-never-checked
  (testing "final reads that ran without a convergence check prove nothing"
    (is (false? (:valid? (checker/check (converge/checker) {} [] {}))))))
