(ns jepsen.hearth.replace-test
  "The node-replacement workload's fault schedule (section 6, G9). Its
  checker is the set checker, proven in set-test."
  (:require [clojure.test :refer [deftest is]]
            [jepsen.generator :as gen]
            [jepsen.nemesis :as n]
            [jepsen.hearth.replace :as replace]))

(deftest the-wiped-node-is-the-lowest-raft-id
  ; gen-configs.sh gives node nX the Raft ID X.
  (is (= "n1" (replace/wipe-target {:nodes ["n4" "n2" "n1" "n5" "n3"]}))))

(deftest the-wipe-nemesis-handles-only-wipe
  (is (= #{:wipe} (set (n/fs (replace/wipe-nemesis))))))

(deftest the-workload-adds-the-wipe-to-the-fault-schedule
  (let [w (replace/workload {:nodes ["n1" "n2" "n3"]} nil)]
    (is (some? (:nemesis w)))
    (is (some? (:nemesis-generator w)))
    (is (= {:type :info :f :wipe :value ["n1"]}
           (-> (gen/op (:nemesis-generator w)
                       {:nodes ["n1" "n2" "n3"]}
                       (gen/context {:concurrency 1 :nodes ["n1" "n2" "n3"]}))
               first
               (select-keys [:type :f :value]))))))
