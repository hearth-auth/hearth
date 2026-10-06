;; Jepsen tests for Hearth cluster mode (openspec change `cluster-jepsen-harness`).
;; Run them with `make jepsen`; see README.md.
;;
;; Jepsen and the Clojure libraries are EPL-1.0. They are test-only, come from
;; Clojars and Maven Central at run time, and are never linked into or shipped
;; with hearth (design.md, Open Question 1).
(defproject hearth-jepsen "0.1.0-SNAPSHOT"
  :description "Jepsen tests for Hearth cluster mode"
  :license {:name "Apache-2.0"
            :url "https://www.apache.org/licenses/LICENSE-2.0"}
  :dependencies [[org.clojure/clojure "1.12.6"]
                 [jepsen "0.3.14"]
                 [org.clojure/data.json "2.5.2"]]
  :main jepsen.hearth.core
  :jvm-opts ["-Xmx4g" "-Djava.awt.headless=true" "-server"]
  :repl-options {:init-ns jepsen.hearth.core})
