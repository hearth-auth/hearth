(ns jepsen.hearth.deferred
  "A generator built at its first op. Jepsen prints the test map, generators
  included, before the run; a lazy seq realized then holds the state of that
  moment, not the state after the run."
  (:require [jepsen.generator :as gen]))

(defrecord Deferred [f g]
  gen/Generator
  (op [_ test ctx]
    (let [g (if (= ::unbuilt g) (f) g)]
      (when-let [[op g'] (gen/op g test ctx)]
        [op (when g' (Deferred. f g'))])))

  (update [this test ctx event]
    (if (= ::unbuilt g)
      this
      (Deferred. f (gen/update g test ctx event)))))

(defn deferred
  "A generator that calls `f` at its first op and then acts as the
  generator `f` returned."
  [f]
  (Deferred. f ::unbuilt))
