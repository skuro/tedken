(ns tedken.core-test
  (:use [midje.sweet])
  (:require [tedken.core :refer :all]
            [environ.core :refer [env]]
            [lock-key.core :refer [decrypt decrypt-as-str encrypt]]))

(defn insecure-request
  "Creates a RING request with no token"
  []
  {:method :post
   :headers []})

(defn secure-request
  "Creases a secure RING request that incoprorates the encrypted token for CSRF protection"
  [token]
  {:method :post
   :headers {"X-CSRF-Token" token}})

(defn dummy-handler
  "A dummy RING handler that always returns OK"
  [request]
  {:status 200
   :headers {}
   :body "Everything is ok!"})

(defn valid?
  "Decrypts the token and validate its dough"
  [token]
  {:pre  [(string? token)]}
  (not (nil? token)))

(defn secured?
  "Checks if the request contain a valid CSRF protection token"
  [request]
  (if-let [token (get-in request [:headers "X-CSRF-Token"])]
    (valid? token)
    false))

(defn wrap-csrf-token
  "RING wrapper that creates and sets encrypted tokens to prevent CSRF attacks"
  [handler]
  (fn [request]
    (if (secured? request)
      (handler request)
      {:status 401
       :headers {}
       :body "You shall not pass!"})))

(def secured-handler (wrap-csrf-token dummy-handler))

(let [secured (secure-request "foobar")
      insecure (insecure-request)]
  (facts "I can protect my requests from CSRF"
         (fact "Insecure requests are forbidden"
               (secured-handler insecure)    => (contains #{[:status 401]}))
         (fact "Secure requests are processed"
               (secured-handler secured)    => (contains #{[:status 200]}))))

(def encoder (java.util.Base64/getEncoder))

(def decoder (java.util.Base64/getDecoder))

(defn secure
  "Encrypts a string using AES"
  [s]
  (-> s
      (encrypt (env :tedken-key))
      (->> (.encodeToString encoder))))

(defn decode
  "Decodes a Base64 string into bytes"
  [encrypted]
  (.decode decoder encrypted))

(defn unwrap
  "Decrypts the token"
  [token]
  (let [decoded (decode token)]
    (String. (decrypt decoded (env :tedken-key)) "UTF-8")))

(let [secret "secret"]
  (fact "I can encrypt the token"
        (secure "test") =not=> "test"
        (secure "test") => (fn [actual]
                             (= "test" (unwrap actual)))))
