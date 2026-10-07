(ns jepsen.hearth.db-test
  "The per-run material: the node configs gen-configs.sh writes."
  (:require [clojure.test :refer [deftest is]]
            [jepsen.hearth.db :as hdb]))

(defn- node-config [read-lag-threshold-ms]
  (slurp (str (hdb/gen-material! ["n1" "n2" "n3"] read-lag-threshold-ms)
              "/nodes/n2/hearth.yaml")))

(deftest the-read-lag-threshold-is-the-server-default-unless-a-test-sets-it
  (is (not (re-find #"read_lag_threshold_ms" (node-config nil))))
  (is (re-find #"(?m)^  read_lag_threshold_ms: 3600000$" (node-config 3600000))))
