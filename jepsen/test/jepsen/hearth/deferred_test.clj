(ns jepsen.hearth.deferred-test
  (:require [clojure.test :refer [deftest is]]
            [jepsen.generator.test :as gt]
            [jepsen.hearth.deferred :as deferred]))

(deftest a-deferred-generator-is-built-at-its-first-op
  ; Jepsen prints the test map, generators included, before the run; a lazy
  ; seq realized then would be empty. The deferred one sees the atom's value
  ; at its first op.
  (let [ks  (atom [])
        g   (deferred/deferred (fn [] (map (fn [k] {:f :read :value k}) @ks)))]
    (is (string? (pr-str g)))
    (reset! ks [1 2 3])
    (is (= [1 2 3] (map :value (gt/quick g))))))

(deftest an-empty-deferred-generator-ends
  (is (= [] (gt/quick (deferred/deferred (constantly nil))))))
