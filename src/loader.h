static const char *loader = " \
local _loader = require'safer.core' \
local function loader(modulename) \
	local packagepath = love.filesystem.getRequirePath() \
	local errors = {''} \
	local modulepath = string.gsub(modulename, '%.', '/') \
	for path in string.gmatch(packagepath, '([^;]+)') do \
		path = path:gsub('%.lua$', '.lus') \
		local filename = string.gsub(path, '%?', modulepath) \
		local file, err = _loader(filename) \
		if file then \
			return file \
		else \
			table.insert(errors, ('no file \"%s\"'):format(filename)) \
		end \
	end \
	return table.concat(errors, '\\n') \
end \
table.insert(package.loaders, 2, loader) \
";
