(ns jepsen.hearth.http
  "The shared HTTPS client and the outcome mapping of design decision 6:

    | Hearth answer                               | Write   | Read    |
    |---------------------------------------------|---------|---------|
    | 2xx                                         | :ok     | :ok     |
    | 503 HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN    | :info   | :fail   |
    | 503 HEARTH_CLUSTER_UNAVAILABLE              | :fail   | :fail   |
    | timeout or connection error                 | :info   | :fail   |
    | any other error                             | :fail   | :fail   |

  Every :fail and :info keeps the HTTP status and the Hearth error code, or
  the client error, in the op's :error."
  (:require [clojure.data.json :as json]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import (java.net ConnectException URI)
           (java.net.http HttpClient HttpClient$Version HttpConnectTimeoutException
                          HttpRequest HttpRequest$BodyPublishers HttpResponse
                          HttpResponse$BodyHandlers HttpTimeoutException)
           (java.security KeyStore)
           (java.security.cert CertificateFactory)
           (java.time Duration)
           (javax.net.ssl SSLContext TrustManagerFactory)))

(def unknown-code "HEARTH_CLUSTER_WRITE_OUTCOME_UNKNOWN")
(def unavailable-code "HEARTH_CLUSTER_UNAVAILABLE")

(def default-timeout-ms
  "Longer than the server's default cluster write timeout (10 s), so a
  server-side 503 arrives before the client gives up."
  15000)

(defn- error-code
  "The Hearth error_code of a parsed body, or nil."
  [body]
  (when (map? body) (get body "error_code")))

(defn outcome
  "Maps one HTTP result to a Jepsen completion: a map with :type and, unless
  :ok, :error. `kind` is :write or :read. `result` is either
  {:status n :body parsed-json} or {:error :timeout | :connect}."
  [kind result]
  (if-let [client-error (:error result)]
    {:type  (if (= kind :write) :info :fail)
     :error {:client client-error}}
    (let [status (:status result)
          code   (error-code (:body result))]
      (cond
        (<= 200 status 299)
        {:type :ok}

        (and (= kind :write) (= status 503) (= code unknown-code))
        {:type :info :error {:status status :code code}}

        :else
        {:type :fail :error {:status status :code code}}))))

(defn complete
  "Completes an invoke `op` with the outcome of `result`."
  [op kind result]
  (merge op (outcome kind result)))

(defn- trust-only
  "An SSLContext that trusts only the certificates in the PEM file."
  [ca-path]
  (let [cf    (CertificateFactory/getInstance "X.509")
        store (doto (KeyStore/getInstance (KeyStore/getDefaultType))
                (.load nil nil))]
    (with-open [in (io/input-stream ca-path)]
      (doseq [[i cert] (map-indexed vector (.generateCertificates cf in))]
        (.setCertificateEntry store (str "ca-" i) cert)))
    (let [tmf (doto (TrustManagerFactory/getInstance
                      (TrustManagerFactory/getDefaultAlgorithm))
                (.init store))]
      (doto (SSLContext/getInstance "TLS")
        (.init nil (.getTrustManagers tmf) nil)))))

(defn client
  "An HTTPS client that trusts the run's CA. The host allowlist accepts
  HTTP/2 since the 2026-10-06 fix, so the JDK's default version is fine."
  [ca-path]
  (-> (HttpClient/newBuilder)
      (.sslContext (trust-only ca-path))
      (.version HttpClient$Version/HTTP_2)
      (.connectTimeout (Duration/ofSeconds 5))
      (.build)))

(defn- parse-body
  [^String s]
  (when-not (empty? s)
    (try (json/read-str s)
         (catch Exception _ s))))

(defn request!
  "Sends one request and returns {:status n :body parsed-json} or
  {:error :timeout | :connect}. Options:

    :method   :get (default), :post, :put, :patch or :delete
    :headers  map of header name to value
    :json     a body to send as JSON
    :form     a map to send as application/x-www-form-urlencoded
    :timeout  milliseconds, default `default-timeout-ms`

  No Origin header: the console checks it against the issuer's origin, and an
  absent header is same-site by design."
  [^HttpClient http url opts]
  (let [body    (cond (contains? opts :json) (json/write-str (:json opts))
                      (contains? opts :form)
                      (->> (:form opts)
                           (map (fn [[k v]]
                                  (str (java.net.URLEncoder/encode (name k) "UTF-8") "="
                                       (java.net.URLEncoder/encode (str v) "UTF-8"))))
                           (str/join "&")))
        ctype   (cond (contains? opts :json) "application/json"
                      (contains? opts :form) "application/x-www-form-urlencoded")
        method  (.toUpperCase (name (:method opts :get)))
        builder (-> (HttpRequest/newBuilder (URI/create url))
                    (.timeout (Duration/ofMillis (:timeout opts default-timeout-ms)))
                    (.method method (if body
                                      (HttpRequest$BodyPublishers/ofString body)
                                      (HttpRequest$BodyPublishers/noBody))))]
    (when ctype (.header builder "Content-Type" ctype))
    (doseq [[k v] (:headers opts)] (.header builder (name k) (str v)))
    (try
      (let [^HttpResponse resp (.send http (.build builder)
                                      (HttpResponse$BodyHandlers/ofString))]
        {:status (.statusCode resp)
         :body   (parse-body (.body resp))})
      (catch HttpConnectTimeoutException _ {:error :connect})
      (catch HttpTimeoutException _ {:error :timeout})
      (catch ConnectException _ {:error :connect})
      (catch java.io.IOException _ {:error :connect}))))
