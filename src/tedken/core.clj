(ns tedken.core
  (:require [environ.core :refer [env]]
            [clojure.string :as s]
            [clojure.data.codec.base64 :as b64]
            [lock-key.core :as sec]
            [crypto.random :as rand]
            [simple-time.core :as time]))

(defn ^String encode
  "Encodes some bytes into a Base64 string"
  [^bytes stuff]
  (String. ^bytes (b64/encode stuff) "utf-8"))

(defn ^bytes decode
  "Decodes a Base64 string into bytes"
  [^String encoded]
  (b64/decode (.getBytes encoded "utf-8")))

(defn ^String encrypt
  "Encrypts a string using AES"
  [^String s]
  (let [bytes (-> s
                  (sec/encrypt (env :tedken-key))
                  encode)]
    bytes))

(defn ^String decrypt
  "Decrypts the token"
  [^String token]
  (let [decoded (decode token)]
    (String. (sec/decrypt decoded (env :tedken-key)) "UTF-8")))

(defn create-token
  "Creates an encrypted token"
  [user stamp nonce]
  (let [dough (s/join ":" [user stamp nonce])]
    (encrypt dough)))

(defn parse-token
  "Parses the token into the constituent pieces. If the token is not parseable, returns nil."
  [^String token]
  (try
    (let [[user stamp nonce] (-> token
                                 decrypt
                                 (s/split #":"))]
      [user (Long/parseLong stamp) nonce])
    (catch Exception e
      nil)))

(defn actual?
  "Verifies that the timestamp in the token is no more than one hour ago"
  [then]
  (let [now  (time/now)
        diff (time/- now (time/datetime then))
        duration (time/duration diff)
        hours (time/timespan->total-hours duration)]
    (< hours 1)))

(defn valid?
  "Validates the information included into the token"
  [user user-fn stamp request]
  (if (and (= user (user-fn request))
           (actual? stamp))
    [user stamp]
    false))

(defn secured?
  "Checks if the request contain a valid CSRF protection token"
  [request user-fn]
  (let [token (get-in request [:headers "X-CSRF-Token"])]
   (if-let [[user stamp nonce] (parse-token (get-in request [:headers "X-CSRF-Token"]))]
     (valid? user user-fn stamp request)
     false)))

(defn unauthorized
  "Returns a Ring response with an unauthorized error code"
  []
  {:status 401
   :headers {}
   :body "You shall not pass!"})

(defn add-token
  "Adds a secure token to the response"
  [request user-fn response]
  (let [user (user-fn request)
        stamp (time/datetime->epoch (time/now))
        nonce (rand/base64 32)
        token (create-token user stamp nonce)]
    (assoc-in response [:headers "X-CSRF-Token"] token)))

(defn apply-security?
  "Filters out HTTP methods for which security is not necessary"
  [request]
  (not (#{:get :head :options} (:request-method request))))

(defn process-unsafe
  "Processes non-mutating requests and adds a token to the response if there is a user context"
  [handler request user-fn]
  (let [response (handler request)]
    (if-let [user (user-fn request response)]
      (add-token request user-fn response)
      response)))

(defn process-safe
  "Checks if the request contains a valid token. If so, processes the request and adds a token to the response."
  [handler request user-fn]
  (if-let [[user stamp] (secured? request user-fn)]
    (let [response (handler request)]
      (add-token request user-fn response))
    (unauthorized)))

(defn wrap-csrf-token
  "RING wrapper that creates and sets encrypted tokens to prevent CSRF attacks. user-fn
   must accept the following arities:

   - (user-fn request)
   - (user-fn request response)

   And must return the user name / ID of the currently logged in user"
  [handler user-fn]
  (fn [request]
    (if (apply-security? request)
      (process-safe   handler request user-fn)
      (process-unsafe handler request user-fn))))
