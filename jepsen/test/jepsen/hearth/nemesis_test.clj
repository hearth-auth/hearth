(ns jepsen.hearth.nemesis-test
  (:require [clojure.test :refer [deftest is]]
            [jepsen.hearth [nemesis :as hn]
                           [revocation :as revocation]]))

(deftest the-injected-delay-is-the-worst-one-way-packet-delay
  ; 200 ms plus up to 50 ms jitter on each peer link, only with :packet.
  (is (= 250 (hn/injected-delay-ms [:kill :packet])))
  (is (= 0 (hn/injected-delay-ms [:partition :kill])))
  (is (= 1900 (revocation/bound-ms (hn/injected-delay-ms [:packet])))))
