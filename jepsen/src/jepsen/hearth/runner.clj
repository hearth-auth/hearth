(ns jepsen.hearth.runner
  "Classifies test results against jepsen/expectations.edn (design decision
  9; spec \"Results are classified as pass, fail, xfail or xpass\"):

    | Expectation | Jepsen :valid? | Result                        |
    |-------------|----------------|-------------------------------|
    | :pass       | true           | pass                          |
    | :pass       | false/:unknown | fail                          |
    | {:xfail G}  | false          | xfail G                       |
    | {:xfail G}  | true           | xpass G (a warning)           |
    | {:xfail G}  | :unknown       | fail: the test could not decide |
    | none        | anything       | fail: every test needs one    |

  A run fails (exit 1) when any result is fail. xfail and xpass do not fail
  it."
  (:require [clojure.edn :as edn]
            [clojure.string :as str]))

(defn- tolerant-read
  "Reads EDN, keeping the value of any tagged literal Jepsen writes."
  [s]
  (edn/read-string {:default (fn [_tag value] value)} s))

(defn read-valid
  "The top-level :valid? of a results.edn file."
  [path]
  (:valid? (tolerant-read (slurp path))))

(defn load-expectations
  "Test name -> :pass or {:xfail \"G<n>\"}."
  [path]
  (tolerant-read (slurp path)))

(defn classify
  "The result of one test: {:result :pass|:fail|:xfail|:xpass} with :gid
  for xfail and xpass."
  [expectation valid?]
  (cond
    (= :pass expectation)
    {:result (if (true? valid?) :pass :fail)}

    (:xfail expectation)
    (case valid?
      false {:result :xfail :gid (:xfail expectation)}
      true  {:result :xpass :gid (:xfail expectation)}
      {:result :fail})

    :else
    {:result :fail}))

(defn verdict
  "Classifies every run, a seq of {:test name :valid? v :store dir}.
  Returns {:rows [...] :exit 0|1}."
  [expectations runs]
  (let [rows (vec (for [{:keys [test valid?] :as run} runs
                        :let [expect (get expectations test)]]
                    (merge run
                           {:expectation expect}
                           (if (nil? expect)
                             {:result :fail :reason "no expectation in expectations.edn"}
                             (classify expect valid?)))))]
    {:rows rows
     :exit (if (some #(= :fail (:result %)) rows) 1 0)}))

(defn report
  "One line per test, then a summary line."
  [{:keys [rows exit]}]
  (let [line (fn [{:keys [result gid test valid? reason store]}]
               (case result
                 :pass  (format "PASS        %s" test)
                 :xfail (format "XFAIL %-5s %s" gid test)
                 :xpass (format "XPASS %-5s %s  (warning: the expected violation did not occur)"
                                gid test)
                 :fail  (format "FAIL        %s  (%s)  %s" test
                                (or reason (str ":valid? " (pr-str valid?)))
                                (or store ""))))
        counts (frequencies (map :result rows))]
    (str (str/join "\n" (map line rows))
         "\n"
         (format "%d pass, %d fail, %d xfail, %d xpass: run %s"
                 (counts :pass 0) (counts :fail 0) (counts :xfail 0) (counts :xpass 0)
                 (if (zero? exit) "PASSED" "FAILED")))))
