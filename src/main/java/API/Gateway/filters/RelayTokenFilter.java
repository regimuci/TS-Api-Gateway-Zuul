package API.Gateway.filters;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class RelayTokenFilter extends ZuulFilter {

    @Override
    public Object run() {
//        RequestContext ctx = RequestContext.getCurrentContext();
        System.out.println("Object run()");
//        Set<String> headers = (Set<String>) ctx.get("ignoredHeaders");
//        headers.remove("authorization");
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());
        return null;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public String filterType() {
        return "pre";
    }

    @Override
    public int filterOrder() {
        return 10000;
    }
}