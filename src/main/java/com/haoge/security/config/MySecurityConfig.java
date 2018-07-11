package com.haoge.security.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// TODO Auto-generated method stub
//		super.configure(http);
		//定制请求的授权规则,允许所有人访问/请求，允许有VIP1角色的访问level1下的所有请求
		http.authorizeRequests().antMatchers("/").permitAll()
		.antMatchers("/level1/**").hasRole("VIP1")
		.antMatchers("/level2/**").hasRole("VIP2")
		.antMatchers("/level3/**").hasRole("VIP3");
		//用userlogin处理登录请求，请求用户名user,密码pwd
		//开启自动配置的登录功能
		http.formLogin().usernameParameter("user").passwordParameter("pwd").loginPage("/userlogin");
		//备注：发送/login请求默认来到security自动生成的登录页面
		//如果重定向到/login?error表示登录失败
		//默认情况下，/login的get请求跳转到登录页面，/login的post请求用来处理登录逻辑
		//如果我们定制了loginPage，则loginPage对应的get请求跳转到登录页面，loginPage对应的post请求用来处理登录逻辑
		
		//注销功能
		http.logout().logoutSuccessUrl("/");//注销成功之后跳转的连接
//		访问/logout表示用户注销，清空session
//		默认注销成功之后会返回/login？logout页面
		
		//开启记住我功能
		http.rememberMe().rememberMeParameter("remeber");
		//登陆成功之后，将cookie发送给浏览器进行保存，以后再访问的时候带着这个cookie就可以免登陆
		//点击注销只有，删除cookie
	}
	//定义认证规则
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		//	super.configure(auth);
		//允许账号zhangsan,密码123456登录，该账号的角色为VIP1,VIP2
		auth.inMemoryAuthentication().withUser("zhangsan").password("123456").roles("VIP1","VIP2")
		.and().withUser("lisi").password("123456").roles("VIP1","VIP3")
		.and().withUser("wangwu").password("123456").roles("VIP3","VIP2");
		
	}
}
