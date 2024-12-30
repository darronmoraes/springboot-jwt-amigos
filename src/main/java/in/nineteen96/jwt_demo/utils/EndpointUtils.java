package in.nineteen96.jwt_demo.utils;

import java.util.List;

public class EndpointUtils {

    public static boolean isPermittedEndpoint(String requestUri, List<String> permittedURIs) {
        return permittedURIs.stream().anyMatch(requestUri::startsWith);
    }
}
