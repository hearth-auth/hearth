(ns jepsen.hearth.auth-test
  "The pure parts of the realm sign-in (authorization code + PKCE through
  the hosted login form)."
  (:require [clojure.test :refer [deftest is]]
            [jepsen.hearth.auth :as auth])
  (:import (java.util Base64)))

(deftest the-pkce-challenge-follows-rfc-7636
  ; RFC 7636 appendix B.
  (is (= "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
         (auth/pkce-challenge "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")))
  (let [v (auth/pkce-verifier)]
    (is (re-matches #"[A-Za-z0-9_-]{43,128}" v))
    (is (not= v (auth/pkce-verifier)))))

(deftest the-client-id-is-the-servers-uuid-v5
  ; hearth derives a declared application's client_id as UUID v5 of
  ; "<realm>/<key>" (src/identity/reconcile.rs); value seen from a server.
  (is (= "824c730a-23bf-52ea-ac8d-6a88f90ed59d" (auth/client-id "jepsen" "harness"))))

(deftest cookies-come-from-set-cookie-headers
  (is (= {"hearth_ui_csrf" "abc" "hearth_ui_session" "s1"}
         (auth/cookies {"set-cookie" ["hearth_ui_csrf=abc; Path=/; Secure; HttpOnly"
                                      "hearth_ui_session=s1; Path=/; SameSite=Lax"]})))
  (is (= {} (auth/cookies {})))
  (is (= "a=1; b=2" (auth/cookie-header {"a" "1" "b" "2"}))))

(deftest the-code-comes-from-the-redirect
  (is (= {:code "c-1" :state "s 1" :iss "https://x"}
         (auth/redirect-params
           "https://harness.jepsen.test/callback?code=c-1&state=s+1&iss=https%3A%2F%2Fx")))
  (is (= {:error "access_denied"}
         (select-keys (auth/redirect-params "https://h/cb?error=access_denied&state=s")
                      [:error]))))

(deftest the-hidden-csrf-field-comes-from-the-form
  (is (= "tok-1" (auth/hidden-field "<input type=\"hidden\" name=\"_csrf\" value=\"tok-1\">"
                                    "_csrf")))
  (is (nil? (auth/hidden-field "<p>no form</p>" "_csrf"))))

(defn- jwt [claims-json]
  (let [enc #(.encodeToString (.withoutPadding (Base64/getUrlEncoder)) (.getBytes ^String %))]
    (str (enc "{\"alg\":\"EdDSA\"}") "." (enc claims-json) ".sig")))

(deftest the-session-id-comes-from-the-access-token
  (is (= "2de0db62-e8ab-9c2e-5539-795bc25de6bd"
         (auth/session-id (jwt "{\"sid\":\"session_2de0db62-e8ab-9c2e-5539-795bc25de6bd\"}"))))
  (is (nil? (auth/session-id (jwt "{\"sid\":\"none\"}")))))
