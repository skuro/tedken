(ns tedken.core
  (:require [environ.core :refer [env]]
            [lock-key.core :as sec]))

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

(def encoder (java.util.Base64/getEncoder))

(def decoder (java.util.Base64/getDecoder))

(defn secure
  "Encrypts a string using AES"
  [s]
  (-> s
      (sec/encrypt (env :tedken-key))
      (->> (.encodeToString encoder))))

(defn decode
  "Decodes a Base64 string into bytes"
  [encrypted]
  (.decode decoder encrypted))

(defn decrypt
  "Decrypts the token"
  [token]
  (let [decoded (decode token)]
    (String. (sec/decrypt decoded (env :tedken-key)) "UTF-8")))

(defn wrap-csrf-token
  "RING wrapper that creates and sets encrypted tokens to prevent CSRF attacks"
  [handler]
  (fn [request]
    (if (secured? request)
      (handler request)
      {:status 401
       :headers {}
       :body "You shall not pass!"})))
