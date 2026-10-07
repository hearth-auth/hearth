(ns jepsen.hearth.secret-test
  "Run credentials never reach a log: Jepsen prints the whole test map,
  db state included, into jepsen.log, which CI uploads as an artifact."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is]]
            [jepsen.util :as util]
            [jepsen.hearth [db :as hdb]
                           [secret :as secret]]))

(def pw "jepsen-planted-password")

(deftest a-secret-prints-redacted-and-reveals-its-value
  (let [s (secret/secret pw)]
    (is (= pw (secret/reveal s)))
    (is (not (str/includes? (str s) pw)))
    (is (not (str/includes? (pr-str s) pw)))))

(deftest the-printed-test-map-holds-no-run-password
  (let [db (hdb/->HearthDB (atom {:password             (secret/secret pw)
                                  :realm-admin-password (secret/secret pw)}))]
    (is (= pw (hdb/realm-admin-password db)))
    (is (not (str/includes? (util/test->str {:name "t" :db db}) pw)))))
