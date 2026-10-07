(ns jepsen.hearth.auth
  "Signs in to the workloads' realm the way a browser-based client does:
  the hosted login form, then authorization code + PKCE with the public
  `harness` application gen-configs.sh declares. Hearth has no password
  grant, and a system-realm token cannot manage another realm's users.

  The login form's session cookie is signed with a per-process secret, so
  one sign-in runs all its steps on one node. The tokens it returns work on
  every node."
  (:require [clojure.data.json :as json]
            [clojure.string :as str]
            [jepsen.hearth [db :as hdb]
                           [http :as http]])
  (:import (java.net URI URLDecoder)
           (java.nio ByteBuffer)
           (java.security MessageDigest SecureRandom)
           (java.util Base64 UUID)))

(def app-key
  "The application key under realms.<realm>.applications in gen-configs.sh."
  "harness")

(def redirect-uri
  "The harness application's redirect URI. Nothing fetches it: the client
  reads the code from the redirect's Location header."
  "https://harness.jepsen.test/callback")

(defn- b64url [^bytes bs]
  (.encodeToString (.withoutPadding (Base64/getUrlEncoder)) bs))

(defn pkce-verifier
  "A fresh PKCE code verifier: 32 random bytes, base64url (43 characters)."
  []
  (let [bs (byte-array 32)]
    (.nextBytes (SecureRandom.) bs)
    (b64url bs)))

(defn pkce-challenge
  "The S256 challenge of `verifier` (RFC 7636 section 4.2)."
  [^String verifier]
  (b64url (.digest (MessageDigest/getInstance "SHA-256") (.getBytes verifier "US-ASCII"))))

(def ^:private app-namespace
  "hearth's UUID v5 namespace for declared applications
  (APP_NAMESPACE in src/identity/reconcile.rs)."
  (byte-array (map unchecked-byte [0x8b 0x07 0x4e 0x8c 0x3e 0x6a 0x5a 0x8e
                                   0x96 0x1d 0x8f 0x2b 0xaa 0xe7 0x1b 0xf4])))

(defn client-id
  "The client_id hearth derives for application `key` of realm `realm`:
  UUID v5 of \"<realm>/<key>\" in its application namespace."
  [realm key]
  (let [md   (doto (MessageDigest/getInstance "SHA-1")
               (.update ^bytes app-namespace)
               (.update (.getBytes (str realm "/" key) "UTF-8")))
        h    (.digest md)
        _    (aset-byte h 6 (unchecked-byte (bit-or (bit-and (aget h 6) 0x0f) 0x50)))
        _    (aset-byte h 8 (unchecked-byte (bit-or (bit-and (aget h 8) 0x3f) 0x80)))
        buf  (ByteBuffer/wrap h)]
    (str (UUID. (.getLong buf) (.getLong buf)))))

(defn cookies
  "name -> value of the cookies in a response's Set-Cookie headers."
  [headers]
  (into {}
        (keep (fn [line]
                (let [[pair] (str/split line #";" 2)
                      [k v]  (str/split pair #"=" 2)]
                  (when (and k v) [(str/trim k) (str/trim v)]))))
        (get headers "set-cookie")))

(defn cookie-header
  "A Cookie header value for the cookie map `jar`."
  [jar]
  (str/join "; " (map (fn [[k v]] (str k "=" v)) jar)))

(defn hidden-field
  "The value of the form input named `field` in `html`, or nil."
  [html field]
  (when (string? html)
    (second (re-find (re-pattern (str "name=\"" field "\" value=\"([^\"]*)\"")) html))))

(defn redirect-params
  "The query parameters of a redirect URL, keyword keys, decoded."
  [url]
  (into {}
        (keep (fn [kv]
                (let [[k v] (str/split kv #"=" 2)]
                  (when (seq k)
                    [(keyword (URLDecoder/decode ^String k "UTF-8"))
                     (URLDecoder/decode (or v "") "UTF-8")]))))
        (some-> (.getRawQuery (URI/create url)) (str/split #"&"))))

(defn- claims
  "The payload of a JWT, unverified: the server issued it to this client."
  [token]
  (let [payload (second (str/split token #"\."))]
    (json/read-str (String. (.decode (Base64/getUrlDecoder) ^String payload) "UTF-8"))))

(defn session-id
  "The session ID in an access token's sid claim, without hearth's
  session_ prefix; nil for a token with no session."
  [access-token]
  (let [sid (get (claims access-token) "sid")]
    (when (and sid (not= "none" sid))
      (str/replace-first sid #"^session_" ""))))

(defn- step
  "Checks one sign-in step's result: an anomaly unless its status is `want`."
  [name want result]
  (when-not (= want (:status result))
    {:step   name
     :status (:status result)
     :error  (or (:error result) (get-in result [:body "error_code"])
                 (get-in result [:body "error"]))}))

(defn sign-in!
  "Signs `email` in to realm `hdb/realm` on `node`. Returns {:access token
  :refresh token :session-id id}, or {:error {:step ...}} naming the step
  that failed. Every step runs on `node`."
  [db node email password]
  (let [http     (hdb/http-client db)
        base     (hdb/node-url node)
        realm    hdb/realm
        cid      (client-id realm app-key)
        login    (str base "/ui/realms/" realm "/login")
        page     (http/request! http login {})
        jar      (cookies (:headers page))
        posted   (http/request! http login
                                {:method  :post
                                 :headers {"Cookie" (cookie-header jar)}
                                 :form    {:_csrf    (hidden-field (:body page) "_csrf")
                                           :email    email
                                           :password password}})
        jar      (merge jar (cookies (:headers posted)))
        verifier (pkce-verifier)
        state    (str (random-uuid))
        authz    (when (= 303 (:status posted))
                   (http/request!
                     http
                     (str base "/ui/realms/" realm "/oauth/authorize?"
                          (str/join "&" (map (fn [[k v]] (str (name k) "="
                                                              (java.net.URLEncoder/encode
                                                                (str v) "UTF-8")))
                                             {:response_type         "code"
                                              :client_id             cid
                                              :redirect_uri          redirect-uri
                                              :state                 state
                                              :scope                 "openid"
                                              :code_challenge        (pkce-challenge verifier)
                                              :code_challenge_method "S256"})))
                     {:headers {"Cookie" (cookie-header jar)}}))
        location (first (get-in authz [:headers "location"]))
        params   (some-> location redirect-params)
        token    (when (and (:code params) (= state (:state params)))
                   (http/request! http (str base "/realms/" realm "/token")
                                  {:method :post
                                   :form   {:grant_type    "authorization_code"
                                            :code          (:code params)
                                            :redirect_uri  redirect-uri
                                            :client_id     cid
                                            :code_verifier verifier}}))]
    (if-let [anomaly (or (step :login-page 200 page)
                         (step :login 303 posted)
                         (step :authorize 303 authz)
                         (when-not (:code params)
                           {:step :authorize :location location})
                         (when-not (= state (:state params))
                           {:step :authorize :error "state mismatch"})
                         (step :token 200 token))]
      {:error anomaly}
      (let [access (get-in token [:body "access_token"])]
        {:access     access
         :refresh    (get-in token [:body "refresh_token"])
         :session-id (session-id access)}))))

(defn sign-in-anywhere!
  "sign-in! on `node`, then on each other node of the test until one works.
  Every step of one attempt runs on one node. Returns sign-in!'s result plus
  :node, or the last attempt's {:error ...}."
  [db test node email password]
  (loop [[at & more] (cons node (remove #{node} (:nodes test)))]
    (let [r (sign-in! db at email password)]
      (cond
        (:access r)  (assoc r :node at)
        (seq more)   (recur more)
        :else        r))))

(defn redeem!
  "Redeems refresh token `refresh` on `node` (grant_type=refresh_token).
  Returns the http/request! result; its body holds the next refresh token."
  [db node refresh]
  (http/request! (hdb/http-client db)
                 (str (hdb/node-url node) "/realms/" hdb/realm "/token")
                 {:method :post
                  :form   {:grant_type    "refresh_token"
                           :refresh_token refresh
                           :client_id     (client-id hdb/realm app-key)}}))

(defn realm-id
  "The UUID of realm `hdb/realm`, from GET /admin/realms with the operator
  token on `node`. Throws when the realm is missing."
  [db node]
  (let [r (http/request! (hdb/http-client db) (str (hdb/node-url node) "/admin/realms")
                         {:headers {"Authorization" (str "Bearer " (hdb/operator-token db))
                                    "X-Realm-ID"    hdb/system-realm}})]
    (or (some #(when (= hdb/realm (get % "name")) (get % "id"))
              (get-in r [:body "items"]))
        (throw (ex-info (str "realm " hdb/realm " not found") {:result (dissoc r :headers)})))))
