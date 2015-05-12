(ns tedken.core
  (:require [environ.core :refer [env]]
            [clojure.data.codec.base64 :as b64]
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

(defn ^String encode
  [^bytes stuff])

(defn ^bytes secure
  "Encrypts a string using AES"
  [^String s]
  (let [ bytes (-> s
                   (sec/encrypt (env :tedken-key))
                   b64/encode)]
    (String. ^bytes bytes "utf-8")))

(defn ^bytes decode
  "Decodes a Base64 string into bytes"
  [^String encrypted]
  (b64/decode (.getBytes encrypted "utf-8")))

(defn ^String decrypt
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
