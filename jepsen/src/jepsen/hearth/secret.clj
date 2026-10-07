(ns jepsen.hearth.secret
  "A run credential that prints as #<secret>. Jepsen prints the whole test
  map, db state included, into jepsen.log, and CI uploads the store.")

(deftype Secret [value]
  Object
  (toString [_] "#<secret>"))

(defmethod print-method Secret [_ ^java.io.Writer w]
  (.write w "#<secret>"))

(defn secret
  "Wraps `value`."
  [value]
  (->Secret value))

(defn reveal
  "The wrapped value; nil for nil."
  [^Secret s]
  (some-> s .-value))
