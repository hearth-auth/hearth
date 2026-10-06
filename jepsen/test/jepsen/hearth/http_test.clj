(ns jepsen.hearth.http-test
  "The outcome mapping of design decision 6 (spec: \"Client answers map to
  Jepsen outcomes\"), fed canned answers."
  (:require [clojure.test :refer [deftest is testing]]
            [jepsen.hearth.http :as http]))

(defn- answer
  "A canned HTTP answer with a Hearth error body."
  [status code]
  {:status status
   :body   {"error" "canned" "error_code" code}})

(def unknown (answer 503 "HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN"))
(def unavailable (answer 503 "HEARTH_CLUSTER_UNAVAILABLE"))

(deftest success-is-ok
  (doseq [status [200 201 204]
          kind   [:write :read]]
    (is (= :ok (:type (http/outcome kind {:status status :body nil})))
        (str kind " " status))))

(deftest an-unknown-write-outcome-is-info
  (let [o (http/outcome :write unknown)]
    (is (= :info (:type o)))
    (is (= {:status 503 :code "HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN"}
           (:error o)))))

(deftest an-unknown-outcome-on-a-read-is-fail
  (is (= :fail (:type (http/outcome :read unknown)))))

(deftest unavailable-is-fail-for-writes-and-reads
  (doseq [kind [:write :read]]
    (let [o (http/outcome kind unavailable)]
      (is (= :fail (:type o)) (str kind))
      (is (= {:status 503 :code "HEARTH_CLUSTER_UNAVAILABLE"} (:error o))
          (str kind)))))

(deftest a-timeout-is-info-for-a-write-and-fail-for-a-read
  (testing "timeout"
    (is (= :info (:type (http/outcome :write {:error :timeout}))))
    (is (= :fail (:type (http/outcome :read {:error :timeout})))))
  (testing "connection error"
    (is (= :info (:type (http/outcome :write {:error :connect}))))
    (is (= :fail (:type (http/outcome :read {:error :connect})))))
  (testing "the history keeps which one it was"
    (is (= {:client :timeout}
           (:error (http/outcome :write {:error :timeout}))))))

(deftest any-other-error-is-fail-and-keeps-its-code
  (doseq [kind [:write :read]]
    (let [o (http/outcome kind (answer 400 "HEARTH_VALIDATION_ERROR"))]
      (is (= :fail (:type o)) (str kind))
      (is (= {:status 400 :code "HEARTH_VALIDATION_ERROR"} (:error o))
          (str kind)))))

(deftest a-503-without-a-cluster-code-is-fail
  (testing "a null error_code, as on every 5xx"
    (is (= {:type :fail :error {:status 503 :code nil}}
           (http/outcome :write (answer 503 nil)))))
  (testing "a body that is not JSON"
    (is (= {:type :fail :error {:status 503 :code nil}}
           (http/outcome :write {:status 503 :body "Service Unavailable"})))))

(deftest complete-merges-the-outcome-into-the-op
  (is (= {:type :info :f :add :value 7
          :error {:status 503 :code "HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN"}}
         (http/complete {:type :invoke :f :add :value 7} :write unknown))))
