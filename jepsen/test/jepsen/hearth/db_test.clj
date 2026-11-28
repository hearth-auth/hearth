(ns jepsen.hearth.db-test
  "The per-run material: the node configs gen-configs.sh writes."
  (:require [clojure.java.shell]
            [clojure.test :refer [deftest is]]
            [jepsen.hearth.db :as hdb]))

(defn- node-config [read-lag-threshold-ms]
  (slurp (str (hdb/gen-material! ["n1" "n2" "n3"] read-lag-threshold-ms)
              "/nodes/n2/hearth.yaml")))

(deftest the-read-lag-threshold-is-the-server-default-unless-a-test-sets-it
  (is (not (re-find #"read_lag_threshold_ms" (node-config nil))))
  (is (re-find #"(?m)^  read_lag_threshold_ms: 3600000$" (node-config 3600000))))

(defn- subject-alt-names [cert-file]
  (:out (clojure.java.shell/sh "openssl" "x509" "-in" cert-file "-noout"
                               "-ext" "subjectAltName")))

(deftest each-peer-certificate-names-its-node-id
  ; Peers refuse a certificate that names another node (design decision 5).
  (let [dir (hdb/gen-material! ["n1" "n2" "n3"] nil)]
    (is (re-find #"URI:urn:hearth:node:2\b" (subject-alt-names (str dir "/n2-peer.crt"))))
    (is (not (re-find #"urn:hearth:node" (subject-alt-names (str dir "/n2-https.crt")))))))
