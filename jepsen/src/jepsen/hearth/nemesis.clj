(ns jepsen.hearth.nemesis
  "The faults of design decision 8, from Jepsen's combined nemesis package,
  plus the heal-and-converge final phase.

    partition         a clean majority/minority split
    partition-leader  isolates the node(s) reporting role leader
    kill              kill -9 of a random minority, then restart from disk
    packet            delay on node-to-node traffic, which is the peer links:
                      tc filters by destination node IP, so the control
                      node's SSH and HTTP are not delayed"
  (:require [clojure.set :as set]
            [clojure.string :as str]
            [jepsen [generator :as gen]
                    [nemesis :as n]]
            [jepsen.nemesis.combined :as combined]
            [jepsen.hearth.converge :as converge]))

(def faults
  "Fault name -> what it adds to the combined package's options."
  {:partition        {:faults #{:partition} :partition-targets [:majority]}
   :partition-leader {:faults #{:partition} :partition-targets [:primaries]}
   :kill             {:faults #{:kill}}
   :packet           {:faults #{:packet}}})

(defn parse-faults
  "Parses a comma-separated --nemesis value into a sorted vector of fault
  keywords. Empty or nil means no faults."
  [s]
  (->> (str/split (or s "") #",")
       (map str/trim)
       (remove str/blank?)
       (map keyword)
       sort
       vec))

(defn- combined-opts
  [db fault-names interval]
  (let [parts (map faults fault-names)]
    {:db        db
     :faults    (apply set/union #{} (map :faults parts))
     :interval  interval
     :partition {:targets (vec (distinct (mapcat :partition-targets parts)))}
     :kill      {:targets [:minority]}
     :packet    {:targets   [:all]
                 :behaviors [{:delay {:time :200ms :jitter :50ms}}]}}))

(defn package
  "A map with :nemesis, :generator (the faults, staggered by `interval`
  seconds), :final-generator (heal every fault, restart killed nodes, then
  :converge) and :perf. `fault-names` are keys of `faults`."
  [{:keys [db fault-names interval recovery-timeout-ms]}]
  ; Only the packages the faults need. combined/nemesis-package would add
  ; its file-corruption nemesis, whose setup downloads a tool onto every node.
  (let [opts (combined-opts db fault-names interval)
        fs   (:faults opts)
        pkg  (combined/compose-packages
               (cond-> []
                 (fs :partition) (conj (combined/partition-package opts))
                 (fs :packet)    (conj (combined/packet-package opts))
                 (fs :kill)      (conj (combined/db-package opts))))
        conv (converge/nemesis {:recovery-timeout-ms recovery-timeout-ms})]
    {:nemesis         (if (seq fault-names)
                        (n/compose [(:nemesis pkg) conv])
                        conv)
     :generator       (:generator pkg)
     :final-generator (gen/phases (gen/log "Healing every fault")
                                  (:final-generator pkg)
                                  (gen/log "Waiting for the nodes to converge")
                                  {:type :info :f :converge})
     :perf            (:perf pkg)}))
