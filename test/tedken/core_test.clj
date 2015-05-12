(ns tedken.core-test
  (:use [midje.sweet]
        [tedken.core])
  (:require [environ.core :refer [env]]))

(defn insecure-request
  "Creates a RING request with no token"
  []
  {:method :post
   :headers []})

(defn secure-request
  "Creases a secure RING request that incoprorates the encrypted token for CSRF protection"
  []
  (let [response (add-token (insecure-request) (constantly "john") {})
        token (get-in response [:headers "X-CSRF-Token"])]
    {:method :post
     :headers {"X-CSRF-Token" token}}))

(defn dummy-handler
  "A dummy RING handler that always returns OK"
  [request]
  {:status 200
   :headers {}
   :body "Everything is ok!"})

(def secured-handler (wrap-csrf-token dummy-handler (constantly "john")))

(fact "Decode is the dual of encode"
      (decode (encode (.getBytes "test"))) => (fn [^bytes b] (= "test" (String. b))))

(fact "Decrypt is the dual of encrypt"
      (decrypt (encrypt "test")) => "test")
