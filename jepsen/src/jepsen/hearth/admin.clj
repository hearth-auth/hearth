(ns jepsen.hearth.admin
  "The realm admin's session, shared by every client of a run, and admin API
  requests made with it. The admin signs in once, after setup, through
  jepsen.hearth.auth; the session goes through Raft, so the token works on
  every node."
  (:require [clojure.tools.logging :refer [info warn]]
            [jepsen.hearth [auth :as auth]
                           [db :as hdb]
                           [http :as http]]))

(defn session!
  "The realm admin's {:token :realm-id}, signing in on the first call. Tries
  each node in turn; throws when none signs the admin in."
  [db test]
  (or (:admin @(:state db))
      (locking db
        (or (:admin @(:state db))
            (loop [[node & more] (:nodes test)]
              (let [r (auth/sign-in! db node hdb/realm-admin-email
                                     (hdb/realm-admin-password db))]
                (cond
                  (:access r)
                  (let [admin {:token    (:access r)
                               :realm-id (auth/realm-id db node)}]
                    (info "realm admin signed in on" node)
                    (swap! (:state db) assoc :admin admin)
                    admin)

                  (seq more)
                  (do (warn "realm admin sign-in failed on" node (:error r))
                      (recur more))

                  :else
                  (throw (ex-info "the realm admin could not sign in on any node"
                                  {:error (:error r)})))))))))

(defn request!
  "An admin API request on `node` as the realm admin: http/request! with
  the bearer token and X-Realm-ID added. `path` starts with /admin."
  [db node path opts]
  (let [{:keys [token realm-id]} (:admin @(:state db))]
    (http/request! (hdb/http-client db) (str (hdb/node-url node) path)
                   (update opts :headers merge {"Authorization" (str "Bearer " token)
                                                "X-Realm-ID"    realm-id}))))
